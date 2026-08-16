#pragma once

// USBHIDInterface: vendor USB HID transport for MeshCore Companion Radio (nRF52840).
//
// Why HID rather than CDC serial:
//   CDC serial is byte-stream oriented; framing is implemented in software with
//   '<' / '>' delimiters (ArduinoSerialInterface).  HID already provides reliable
//   64-byte report boundaries at the USB level, so no stream parser is needed.
//   This transport wraps Companion protocol frames in a small transport header
//   inside each 64-byte HID report and reassembles them before handing the
//   complete frame to the existing MeshCore Companion handler.

#ifdef MESH_USB_HID

#include "../BaseSerialInterface.h"
#include <Adafruit_TinyUSB.h>

// ── HID report geometry ────────────────────────────────────────────────────
// Each USB HID report is exactly 64 bytes (no Report-ID byte in the descriptor).
#define HID_REPORT_SIZE   64
// Transport header occupies the first 8 bytes of every report.
#define HID_HEADER_SIZE   8
// Usable payload bytes per report.
#define HID_PAYLOAD_SIZE  (HID_REPORT_SIZE - HID_HEADER_SIZE)  // 56

// Maximum reassembled logical message.
// Must be >= MAX_FRAME_SIZE (176).  512 bytes → ceil(512/56) = 10 fragments max.
#define HID_MAX_MSG_SIZE  512

// ── Transport frame flags ──────────────────────────────────────────────────
#define HID_FLAG_FIRST_FRAGMENT  0x01u  // first (or only) fragment of a message
#define HID_FLAG_MORE_FRAGMENTS  0x02u  // more fragments follow
#define HID_FLAG_RESPONSE        0x04u  // frame is a response (device → host)
#define HID_FLAG_ERROR           0x08u  // error indication
#define HID_FLAG_EVENT           0x10u  // unsolicited event

// ── HID report layout (8-byte header + 56-byte payload = 64 bytes) ─────────
// All multi-byte fields are little-endian.
struct __attribute__((packed)) HidTransportFrame {
    uint8_t  version;         // protocol version; always HID_TRANSPORT_VERSION (1)
    uint8_t  flags;           // HID_FLAG_* bitmask
    uint8_t  fragment;        // 0-based fragment index within this message
    uint8_t  reserved;        // must be 0
    uint16_t sequence;        // message sequence number (wraps at 65535→0)
    uint16_t payload_length;  // total logical message length in bytes (all fragments)
    uint8_t  payload[HID_PAYLOAD_SIZE];
};

static_assert(sizeof(HidTransportFrame) == HID_REPORT_SIZE,
              "HidTransportFrame size must equal HID_REPORT_SIZE (64)");

// ── Queue sizes ─────────────────────────────────────────────────────────────
// Receive side: raw 64-byte reports enqueued inside the TinyUSB callback.
#define HID_RECV_QUEUE_SIZE  8

// Send side: logical Companion frames queued by writeFrame(), fragmented later.
#define HID_SEND_QUEUE_SIZE  4

// Maximum outgoing logical frame (matches MAX_FRAME_SIZE + 1 from BaseSerialInterface.h)
#define HID_SEND_FRAME_SIZE  (MAX_FRAME_SIZE + 1)

// ── USBHIDInterface ─────────────────────────────────────────────────────────
// Implements BaseSerialInterface so it can be registered with MultiSerialInterface
// alongside BLE / serial / wifi transports without any changes to the Companion
// protocol handler (MyMesh).
//
// Usage:
//   // global scope (TinyUSB registers the HID interface before setup() runs)
//   USBHIDInterface usb_hid_interface;
//
//   void setup() {
//     usb_hid_interface.begin();
//     interface_manager.addInterface(InterfaceType::HID, &usb_hid_interface);
//     the_mesh.startInterface(interface_manager);
//   }
//
//   void loop() {
//     the_mesh.loop();
//     interface_manager.loop();   // drives USBHIDInterface::loop()
//   }

class USBHIDInterface : public BaseSerialInterface {
public:
    // Must be instantiated in global scope so that the Adafruit_USBD_HID
    // constructor runs before initVariant() starts TinyUSB.
    USBHIDInterface();

    // Register TinyUSB callbacks and start the HID interface.
    // Call once in setup() before the_mesh.startInterface().
    void begin();

    // ── BaseSerialInterface ──────────────────────────────────────────────
    void   enable()             override;
    void   disable()            override;
    bool   isEnabled()    const override { return _enabled; }
    bool   isConnected()  const override;
    bool   isWriteBusy()  const override;

    // Queue a complete Companion frame for fragmented transmission.
    size_t writeFrame(const uint8_t src[], size_t len) override;

    // Reassemble the next complete Companion frame from received HID reports.
    // Returns 0 when no complete frame is available.
    size_t checkRecvFrame(uint8_t dest[]) override;

    // Drive the outgoing fragment transmitter; call from main loop.
    void   loop() override;

private:
    static USBHIDInterface* _instance;  // singleton for TinyUSB callback

    Adafruit_USBD_HID _usb_hid;  // TinyUSB HID class (must outlive setup())
    bool     _enabled;
    uint16_t _tx_sequence;   // sequence number for next outgoing message

    // ── Receive side ─────────────────────────────────────────────────────
    // Raw HID reports enqueued inside the TinyUSB OUTPUT callback (ISR context).
    // Processed (reassembled) in checkRecvFrame() from the main loop.
    struct RawReport {
        uint8_t data[HID_REPORT_SIZE];
    };
    volatile uint8_t _recv_head;  // consumer index (main loop)
    volatile uint8_t _recv_tail;  // producer index (ISR/callback)
    RawReport _recv_queue[HID_RECV_QUEUE_SIZE];

    // Reassembly state – reset on error or after a complete message is delivered.
    bool     _asm_active;         // true while a multi-fragment message is in progress
    uint16_t _asm_sequence;       // expected sequence number
    uint8_t  _asm_next_frag;      // next expected fragment index
    uint16_t _asm_expected_len;   // total payload length (from first fragment)
    uint16_t _asm_received;       // bytes assembled so far
    uint8_t  _asm_buf[HID_MAX_MSG_SIZE];

    // ── Send side ─────────────────────────────────────────────────────────
    // Logical frames enqueued by writeFrame(); fragmented in loop().
    struct LogicalFrame {
        uint16_t len;
        uint8_t  buf[HID_SEND_FRAME_SIZE];
    };
    uint8_t _send_head;   // consumer index
    uint8_t _send_tail;   // producer index
    LogicalFrame _send_queue[HID_SEND_QUEUE_SIZE];

    // Fragmentation state for the frame currently being sent.
    bool     _tx_in_prog;     // true while sending fragments for _send_queue[_send_head]
    uint8_t  _tx_frag;        // next fragment index to transmit
    uint16_t _tx_curr_seq;    // sequence number for the current outgoing message

    // ── Helpers ───────────────────────────────────────────────────────────
    void resetReassembly();

    // Attempt to assemble the next received raw report into dest[].
    // Returns true and sets *out_len when a complete frame has been assembled.
    bool processRawReport(const uint8_t* data, uint8_t* dest, size_t* out_len);

    // Transmit the next pending fragment from the send queue.
    // Returns true if a fragment was sent.
    bool sendNextFragment();

    // TinyUSB callback: host → device OUTPUT report received.
    static void setReportCallback(uint8_t report_id, hid_report_type_t report_type,
                                   uint8_t const* buffer, uint16_t bufsize);
};

#endif  // MESH_USB_HID
