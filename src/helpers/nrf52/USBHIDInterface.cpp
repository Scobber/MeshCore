// USBHIDInterface.cpp — vendor USB HID transport for MeshCore Companion Radio.
//
// Design notes
// ────────────
// MeshCore's existing serial transport (ArduinoSerialInterface) is a byte-stream
// with '<' / '>' delimiters for framing.  This HID transport avoids that parser
// entirely: USB HID already guarantees 64-byte report boundaries, so framing
// reduces to a small 8-byte header carried inside each report.
//
// Fragmentation is necessary because Companion protocol frames can be up to
// MAX_FRAME_SIZE (176) bytes while each HID report carries only 56 bytes of
// payload (64 − 8 byte header).  Reassembly is in-order, sequence-checked and
// deterministic; there is no retransmission because USB already delivers reliably.
//
// The TinyUSB OUTPUT callback runs in interrupt context; it only enqueues a raw
// 64-byte copy into _recv_queue.  All protocol work happens in the main loop
// (checkRecvFrame / loop), matching MeshCore's polling model.

#include "USBHIDInterface.h"

#ifdef MESH_USB_HID

#define HID_TRANSPORT_VERSION  1u

// ── HID report descriptor ─────────────────────────────────────────────────
// Vendor-defined usage page 0xFF00.  No Report IDs.  Two fixed-size reports:
//   INPUT  64 bytes  (device → host, Companion responses / events)
//   OUTPUT 64 bytes  (host → device, Companion commands)
// Standard HID usages (keyboard, mouse, consumer) are intentionally absent.
static const uint8_t _desc_hid_report[] = {
    0x06, 0x00, 0xFF,   // Usage Page (Vendor-defined 0xFF00)
    0x09, 0x01,         // Usage (Vendor Usage 1)
    0xA1, 0x01,         // Collection (Application)
    // INPUT report — device → host
    0x09, 0x01,         //   Usage (Vendor Usage 1)
    0x15, 0x00,         //   Logical Minimum (0)
    0x26, 0xFF, 0x00,   //   Logical Maximum (255)
    0x75, 0x08,         //   Report Size (8 bits)
    0x95, 0x40,         //   Report Count (64)
    0x81, 0x02,         //   Input (Data, Variable, Absolute)
    // OUTPUT report — host → device
    0x09, 0x01,         //   Usage (Vendor Usage 1)
    0x15, 0x00,         //   Logical Minimum (0)
    0x26, 0xFF, 0x00,   //   Logical Maximum (255)
    0x75, 0x08,         //   Report Size (8 bits)
    0x95, 0x40,         //   Report Count (64)
    0x91, 0x02,         //   Output (Data, Variable, Absolute)
    0xC0                // End Collection
};

// ── Singleton pointer (used only inside the TinyUSB callback) ─────────────
USBHIDInterface* USBHIDInterface::_instance = nullptr;

// ── Constructor ───────────────────────────────────────────────────────────
// This runs before setup() so that Adafruit_USBD_HID registers itself with
// TinyUSB before the USB device is started by initVariant().
USBHIDInterface::USBHIDInterface()
    : _usb_hid(_desc_hid_report, sizeof(_desc_hid_report),
                HID_ITF_PROTOCOL_NONE,
                2 /* polling interval, ms */,
                true /* enable OUT endpoint for host→device reports */)
    , _enabled(false)
    , _tx_sequence(0)
    , _recv_head(0)
    , _recv_tail(0)
    , _asm_active(false)
    , _asm_sequence(0)
    , _asm_next_frag(0)
    , _asm_expected_len(0)
    , _asm_received(0)
    , _send_head(0)
    , _send_tail(0)
    , _tx_in_prog(false)
    , _tx_frag(0)
    , _tx_curr_seq(0)
{
    _instance = this;
}

// ── begin() ───────────────────────────────────────────────────────────────
void USBHIDInterface::begin() {
    // Register the OUTPUT (host→device) report callback; the INPUT callback
    // is not used (we push reports with sendReport() directly).
    _usb_hid.setReportCallback(nullptr, setReportCallback);
    _usb_hid.begin();
    // USB enumeration happens asynchronously; isConnected() polls TinyUSBDevice.
}

// ── enable / disable ──────────────────────────────────────────────────────
void USBHIDInterface::enable() {
    _enabled = true;
    _recv_head = 0;
    _recv_tail = 0;
    _send_head = 0;
    _send_tail = 0;
    _tx_in_prog = false;
    _tx_sequence = 0;
    resetReassembly();
}

void USBHIDInterface::disable() {
    _enabled = false;
}

// ── isConnected ───────────────────────────────────────────────────────────
bool USBHIDInterface::isConnected() const {
    // The USB host is present once TinyUSBDevice is mounted.
    return _enabled && TinyUSBDevice.mounted();
}

// ── isWriteBusy ───────────────────────────────────────────────────────────
bool USBHIDInterface::isWriteBusy() const {
    if (!_enabled) return false;
    // Signal busy when ≥ 3/4 of send queue slots are in use.
    uint8_t used = (uint8_t)((_send_tail - _send_head + HID_SEND_QUEUE_SIZE) % HID_SEND_QUEUE_SIZE);
    return used >= (HID_SEND_QUEUE_SIZE * 3 / 4);
}

// ── writeFrame ────────────────────────────────────────────────────────────
// Enqueue a complete Companion frame for fragmented HID transmission.
// Fragmentation itself happens in loop() / sendNextFragment().
size_t USBHIDInterface::writeFrame(const uint8_t src[], size_t len) {
    if (!_enabled || len == 0 || len > HID_MAX_MSG_SIZE) return 0;

    // Check for a free send-queue slot.
    uint8_t next_tail = (_send_tail + 1) % HID_SEND_QUEUE_SIZE;
    if (next_tail == _send_head) {
        // Queue full; caller may retry.
        return 0;
    }

    _send_queue[_send_tail].len = (uint16_t)len;
    memcpy(_send_queue[_send_tail].buf, src, len);
    _send_tail = next_tail;
    return len;
}

// ── checkRecvFrame ────────────────────────────────────────────────────────
// Drain raw received HID reports and reassemble them into a complete Companion
// frame.  Returns the frame length when a complete frame is ready; 0 otherwise.
//
// Called by MyMesh::checkSerialInterface() on every main-loop iteration.
size_t USBHIDInterface::checkRecvFrame(uint8_t dest[]) {
    if (!_enabled) return 0;

    // Process any raw reports that were enqueued by the TinyUSB callback.
    while (_recv_head != _recv_tail) {
        uint8_t idx = _recv_head;
        // Advance head before processing so a new callback can refill that slot.
        _recv_head = (_recv_head + 1) % HID_RECV_QUEUE_SIZE;

        size_t out_len = 0;
        if (processRawReport(_recv_queue[idx].data, dest, &out_len)) {
            return out_len;
        }
    }
    return 0;
}

// ── loop ──────────────────────────────────────────────────────────────────
// Drive the outgoing fragment transmitter.  Called from interface_manager.loop()
// on every main-loop iteration.  Sends at most one HID report per call so it
// does not monopolise CPU.
void USBHIDInterface::loop() {
    if (!_enabled) return;
    if (_send_head == _send_tail) return;     // nothing to send

    if (!isConnected()) return;               // USB host not ready
    if (!_usb_hid.ready()) return;            // IN endpoint still busy

    sendNextFragment();
}

// ── resetReassembly ───────────────────────────────────────────────────────
void USBHIDInterface::resetReassembly() {
    _asm_active       = false;
    _asm_sequence     = 0;
    _asm_next_frag    = 0;
    _asm_expected_len = 0;
    _asm_received     = 0;
}

// ── processRawReport ──────────────────────────────────────────────────────
// Validate one raw 64-byte HID report and advance the reassembly state machine.
// Returns true and writes to dest[] when a complete Companion frame is ready.
bool USBHIDInterface::processRawReport(const uint8_t* data, uint8_t* dest, size_t* out_len) {
    const HidTransportFrame* f = reinterpret_cast<const HidTransportFrame*>(data);

    // Version check: reject unknown protocol versions immediately.
    if (f->version != HID_TRANSPORT_VERSION) {
        resetReassembly();
        return false;
    }

    const bool is_first = (f->flags & HID_FLAG_FIRST_FRAGMENT) != 0;
    const bool has_more = (f->flags & HID_FLAG_MORE_FRAGMENTS) != 0;
    const uint16_t total_len = f->payload_length;

    if (is_first) {
        // ── Start of a new message ────────────────────────────────────────
        if (total_len == 0 || total_len > HID_MAX_MSG_SIZE) {
            // Invalid total length; discard.
            resetReassembly();
            return false;
        }
        if (_asm_active) {
            // Previous message was not completed; silently discard it.
            resetReassembly();
        }
        if (f->fragment != 0) {
            // FIRST_FRAGMENT must have fragment index 0.
            return false;
        }
        _asm_sequence     = f->sequence;
        _asm_expected_len = total_len;
        _asm_next_frag    = 0;
        _asm_received     = 0;
        _asm_active       = true;
    } else {
        // ── Continuation fragment ─────────────────────────────────────────
        if (!_asm_active) {
            // No reassembly in progress; silently discard stale fragment.
            return false;
        }
        if (f->sequence != _asm_sequence) {
            // Sequence mismatch: either a new message started without FIRST or
            // a fragment was lost.  Reset so the host can start over.
            resetReassembly();
            return false;
        }
        if (f->fragment != _asm_next_frag) {
            // Out-of-order fragment; USB is reliable so this indicates a bug on
            // the host.  Reset and force the host to retransmit from scratch.
            resetReassembly();
            return false;
        }
        // Validate the total_length field matches what we saw in the first fragment.
        if (f->payload_length != _asm_expected_len) {
            resetReassembly();
            return false;
        }
    }

    // ── Copy payload bytes into the reassembly buffer ─────────────────────
    uint16_t remaining  = _asm_expected_len - _asm_received;
    uint16_t copy_len   = (remaining < (uint16_t)HID_PAYLOAD_SIZE)
                          ? remaining
                          : (uint16_t)HID_PAYLOAD_SIZE;

    memcpy(_asm_buf + _asm_received, f->payload, copy_len);
    _asm_received += copy_len;
    _asm_next_frag++;

    if (!has_more) {
        // ── Last fragment: deliver complete message ────────────────────────
        if (_asm_received != _asm_expected_len) {
            // Byte count mismatch; discard.
            resetReassembly();
            return false;
        }
        memcpy(dest, _asm_buf, _asm_expected_len);
        *out_len = _asm_expected_len;
        resetReassembly();
        return true;
    }

    return false;  // message not yet complete
}

// ── sendNextFragment ──────────────────────────────────────────────────────
// Build and transmit one HID INPUT report for the frame at _send_queue[_send_head].
// Returns true if a report was successfully queued into TinyUSB.
bool USBHIDInterface::sendNextFragment() {
    if (_send_head == _send_tail) return false;

    if (!_tx_in_prog) {
        // Assign a new sequence number when we start transmitting a new message.
        _tx_frag     = 0;
        _tx_curr_seq = _tx_sequence++;
        _tx_in_prog  = true;
    }

    const LogicalFrame& lf = _send_queue[_send_head];
    const uint16_t offset   = (uint16_t)_tx_frag * (uint16_t)HID_PAYLOAD_SIZE;
    const uint16_t remaining = lf.len - offset;
    const uint16_t copy_len  = (remaining < (uint16_t)HID_PAYLOAD_SIZE)
                                ? remaining
                                : (uint16_t)HID_PAYLOAD_SIZE;
    const bool has_more = (offset + copy_len < lf.len);

    HidTransportFrame report;
    memset(&report, 0, sizeof(report));
    report.version        = HID_TRANSPORT_VERSION;
    report.flags          = (uint8_t)((_tx_frag == 0 ? HID_FLAG_FIRST_FRAGMENT : 0u)
                             | (has_more ? HID_FLAG_MORE_FRAGMENTS : 0u)
                             | HID_FLAG_RESPONSE);  // all device-originated frames are responses
    report.fragment       = _tx_frag;
    report.reserved       = 0;
    report.sequence       = _tx_curr_seq;
    report.payload_length = lf.len;
    memcpy(report.payload, lf.buf + offset, copy_len);

    // Report ID 0 = no Report ID in descriptor; raw 64-byte report is sent.
    if (!_usb_hid.sendReport(0, reinterpret_cast<uint8_t*>(&report), HID_REPORT_SIZE)) {
        // USB IN endpoint not ready; leave fragment state in place and retry next loop().
        return false;
    }

    _tx_frag++;

    if (!has_more) {
        // All fragments for this logical frame have been sent; dequeue.
        _tx_in_prog = false;
        _send_head  = (_send_head + 1) % HID_SEND_QUEUE_SIZE;
    }

    return true;
}

// ── TinyUSB OUTPUT report callback ───────────────────────────────────────
// Called from interrupt / USB task context when the host sends a 64-byte OUTPUT
// report (host → device Companion command).  Only copies the raw bytes into the
// receive queue; all protocol processing happens in checkRecvFrame().
void USBHIDInterface::setReportCallback(uint8_t         report_id,
                                         hid_report_type_t report_type,
                                         uint8_t const*  buffer,
                                         uint16_t        bufsize) {
    (void)report_id;
    (void)report_type;

    if (!_instance || bufsize != HID_REPORT_SIZE) return;

    uint8_t next_tail = (_instance->_recv_tail + 1) % HID_RECV_QUEUE_SIZE;
    if (next_tail == _instance->_recv_head) {
        // Receive queue full; drop the report rather than block the USB stack.
        return;
    }

    memcpy(_instance->_recv_queue[_instance->_recv_tail].data, buffer, HID_REPORT_SIZE);
    _instance->_recv_tail = next_tail;
}

#endif  // MESH_USB_HID
