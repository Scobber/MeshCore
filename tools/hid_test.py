#!/usr/bin/env python3
"""
hid_test.py — MeshCore USB HID Companion transport host-side test utility.

Sends a CMD_DEVICE_QUERY request over USB HID, reassembles the response and
prints the decoded device-info fields.

Requirements
────────────
    pip install hid

On Linux you may also need:
    sudo apt-get install libhidapi-hidraw0   # or libhidapi-libusb0

udev rule (Linux) — allow non-root access to the device:
    SUBSYSTEM=="hidraw", ATTRS{idVendor}=="XXXX", ATTRS{idProduct}=="XXXX", MODE="0666"

    Replace XXXX with the VID/PID printed by this script when run with --list.

Usage
─────
    # List all HID devices to find VID/PID:
    python3 hid_test.py --list

    # Send CMD_DEVICE_QUERY and print the response:
    python3 hid_test.py --vid 0x239A --pid 0x0029

    # Use a specific serial number:
    python3 hid_test.py --vid 0x239A --pid 0x0029 --serial ABC123

    # Dump raw bytes instead of decoded output:
    python3 hid_test.py --vid 0x239A --pid 0x0029 --raw
"""

import argparse
import struct
import sys
import time
import traceback

try:
    import hid
except ImportError:
    print("ERROR: 'hid' package not found.  Install with:  pip install hid")
    sys.exit(1)

# ── Transport constants (must match USBHIDInterface.h) ─────────────────────
HID_REPORT_SIZE    = 64
HID_HEADER_SIZE    = 8
HID_PAYLOAD_SIZE   = HID_REPORT_SIZE - HID_HEADER_SIZE   # 56
HID_MAX_MSG_SIZE   = 512
HID_TRANSPORT_VER  = 1

FLAG_FIRST_FRAGMENT = 0x01
FLAG_MORE_FRAGMENTS = 0x02
FLAG_RESPONSE       = 0x04
FLAG_ERROR          = 0x08
FLAG_EVENT          = 0x10

# Companion protocol codes (from MyMesh.cpp)
CMD_DEVICE_QUERY      = 22    # 0x16
RESP_CODE_DEVICE_INFO = 13    # 0x0D
FIRMWARE_VER_CODE     = 13    # current firmware protocol version

# ── Transport frame packing/unpacking ──────────────────────────────────────
# Layout: version(1) flags(1) fragment(1) reserved(1) sequence(2LE) payload_len(2LE) payload(56)

HEADER_FMT = "<BBBBHH"   # 8 bytes


def pack_report(version, flags, fragment, sequence, payload_length, payload_bytes):
    """Build a 64-byte HID report from header fields and payload bytes."""
    assert len(payload_bytes) <= HID_PAYLOAD_SIZE, "payload too large"
    header = struct.pack(HEADER_FMT, version, flags, fragment, 0, sequence, payload_length)
    padded_payload = payload_bytes.ljust(HID_PAYLOAD_SIZE, b'\x00')
    return header + padded_payload[:HID_PAYLOAD_SIZE]


def unpack_report(data):
    """Parse a 64-byte HID report.  Returns (header_dict, payload_bytes)."""
    assert len(data) >= HID_REPORT_SIZE, f"short report: {len(data)} bytes"
    version, flags, fragment, reserved, sequence, payload_length = \
        struct.unpack_from(HEADER_FMT, data, 0)
    payload = bytes(data[HID_HEADER_SIZE:HID_HEADER_SIZE + HID_PAYLOAD_SIZE])
    return {
        "version":        version,
        "flags":          flags,
        "fragment":       fragment,
        "reserved":       reserved,
        "sequence":       sequence,
        "payload_length": payload_length,
    }, payload


# ── Fragmentation ──────────────────────────────────────────────────────────

def fragment_message(msg_bytes, sequence):
    """
    Split a logical Companion message into one or more 64-byte HID reports.

    Yields each report as bytes(64).
    """
    total_len   = len(msg_bytes)
    offset      = 0
    fragment    = 0

    while offset < total_len:
        chunk    = msg_bytes[offset:offset + HID_PAYLOAD_SIZE]
        is_first = (fragment == 0)
        has_more = (offset + len(chunk) < total_len)

        flags = 0
        if is_first:
            flags |= FLAG_FIRST_FRAGMENT
        if has_more:
            flags |= FLAG_MORE_FRAGMENTS

        report = pack_report(
            version        = HID_TRANSPORT_VER,
            flags          = flags,
            fragment       = fragment,
            sequence       = sequence,
            payload_length = total_len,
            payload_bytes  = chunk,
        )
        yield report

        offset   += len(chunk)
        fragment += 1


# ── Reassembly ─────────────────────────────────────────────────────────────

class Reassembler:
    def __init__(self):
        self.reset()

    def reset(self):
        self._active       = False
        self._sequence     = None
        self._next_frag    = 0
        self._expected_len = 0
        self._buf          = bytearray()

    def feed(self, report_data):
        """
        Feed a raw 64-byte HID report.  Returns the reassembled message bytes
        when a complete message is ready, or None otherwise.
        """
        hdr, payload = unpack_report(report_data)

        if hdr["version"] != HID_TRANSPORT_VER:
            print(f"  [WARN] unknown transport version {hdr['version']}, discarding")
            self.reset()
            return None

        is_first = bool(hdr["flags"] & FLAG_FIRST_FRAGMENT)
        has_more = bool(hdr["flags"] & FLAG_MORE_FRAGMENTS)
        total_len = hdr["payload_length"]

        if is_first:
            if total_len == 0 or total_len > HID_MAX_MSG_SIZE:
                print(f"  [WARN] invalid payload_length={total_len}, discarding")
                self.reset()
                return None
            if hdr["fragment"] != 0:
                print(f"  [WARN] FIRST_FRAGMENT with fragment={hdr['fragment']}, discarding")
                self.reset()
                return None
            self.reset()
            self._active       = True
            self._sequence     = hdr["sequence"]
            self._expected_len = total_len
            self._next_frag    = 0
        else:
            if not self._active:
                print(f"  [WARN] continuation fragment without active reassembly, discarding")
                return None
            if hdr["sequence"] != self._sequence:
                print(f"  [WARN] sequence mismatch (got {hdr['sequence']}, "
                      f"expected {self._sequence}), resetting")
                self.reset()
                return None
            if hdr["fragment"] != self._next_frag:
                print(f"  [WARN] fragment out of order (got {hdr['fragment']}, "
                      f"expected {self._next_frag}), resetting")
                self.reset()
                return None
            if hdr["payload_length"] != self._expected_len:
                print(f"  [WARN] payload_length changed mid-message, resetting")
                self.reset()
                return None

        remaining = self._expected_len - len(self._buf)
        copy_len  = min(remaining, HID_PAYLOAD_SIZE)
        self._buf.extend(payload[:copy_len])
        self._next_frag += 1

        if not has_more:
            if len(self._buf) != self._expected_len:
                print(f"  [WARN] byte count mismatch ({len(self._buf)} vs "
                      f"{self._expected_len}), discarding")
                self.reset()
                return None
            result = bytes(self._buf)
            self.reset()
            return result

        return None


# ── Companion response decoder ─────────────────────────────────────────────

def decode_device_info(resp):
    """
    Decode a RESP_CODE_DEVICE_INFO payload (command 13, structure from MyMesh.cpp).

    Offset layout (from MyMesh::handleCmdFrame for CMD_DEVICE_QUERY):
      [0]      RESP_CODE_DEVICE_INFO (13)
      [1]      FIRMWARE_VER_CODE
      [2]      MAX_CONTACTS / 2
      [3]      MAX_GROUP_CHANNELS
      [4..7]   ble_pin (uint32, LE)
      [8..19]  FIRMWARE_BUILD_DATE (12 bytes, null-padded)
      [20..59] manufacturer name (40 bytes, null-terminated)
      [60..79] FIRMWARE_VERSION string (20 bytes, null-terminated)
      [80]     repeat enabled flag (v9+)
      [81]     path_hash_mode (v10+)
    """
    if len(resp) < 2:
        print("  [ERROR] response too short")
        return
    if resp[0] != RESP_CODE_DEVICE_INFO:
        print(f"  [ERROR] unexpected response code 0x{resp[0]:02X}")
        return

    print(f"  firmware_ver_code   : {resp[1]}")
    if len(resp) > 2:
        print(f"  max_contacts (×2)   : {resp[2] * 2}")
    if len(resp) > 3:
        print(f"  max_group_channels  : {resp[3]}")
    if len(resp) >= 8:
        ble_pin = struct.unpack_from("<I", resp, 4)[0]
        print(f"  ble_pin             : {ble_pin}")
    if len(resp) >= 20:
        build_date = resp[8:20].split(b'\x00')[0].decode('ascii', errors='replace')
        print(f"  build_date          : {build_date!r}")
    if len(resp) >= 60:
        mfr = resp[20:60].split(b'\x00')[0].decode('utf-8', errors='replace')
        print(f"  manufacturer        : {mfr!r}")
    if len(resp) >= 80:
        fw_ver = resp[60:80].split(b'\x00')[0].decode('utf-8', errors='replace')
        print(f"  firmware_version    : {fw_ver!r}")
    if len(resp) >= 81:
        print(f"  repeat_enabled      : {bool(resp[80])}")
    if len(resp) >= 82:
        print(f"  path_hash_mode      : {resp[81]}")


# ── CLI ────────────────────────────────────────────────────────────────────

def cmd_list(_args):
    """List all HID devices visible to the OS."""
    devices = hid.enumerate()
    if not devices:
        print("No HID devices found.")
        return
    for d in devices:
        print(f"  VID=0x{d['vendor_id']:04X}  PID=0x{d['product_id']:04X}"
              f"  path={d['path'].decode(errors='replace')!r}"
              f"  product={d.get('product_string','')!r}"
              f"  serial={d.get('serial_number','')!r}"
              f"  usage_page=0x{d['usage_page']:04X}")


def cmd_query(args):
    """Open the device, send CMD_DEVICE_QUERY and print the decoded response."""
    vid = args.vid
    pid = args.pid
    serial = args.serial or None

    print(f"Opening HID device  VID=0x{vid:04X}  PID=0x{pid:04X}"
          + (f"  serial={serial!r}" if serial else ""))

    dev = hid.device()
    try:
        dev.open(vid, pid, serial)
    except Exception as exc:
        print(f"ERROR: could not open device: {exc}")
        print("Tip: use --list to see all available devices.")
        sys.exit(1)

    mfr  = dev.get_manufacturer_string()
    prod = dev.get_product_string()
    sn   = dev.get_serial_number_string()
    print(f"  manufacturer  : {mfr!r}")
    print(f"  product       : {prod!r}")
    print(f"  serial        : {sn!r}")

    # ── Build CMD_DEVICE_QUERY payload ────────────────────────────────────
    # payload[0] = CMD_DEVICE_QUERY (22)
    # payload[1] = app_target_ver  (13 = current protocol version)
    payload = bytes([CMD_DEVICE_QUERY, FIRMWARE_VER_CODE])

    print(f"\nSending CMD_DEVICE_QUERY (0x{CMD_DEVICE_QUERY:02X})  "
          f"payload={payload.hex()}  ({len(payload)} bytes)")

    sequence = 0
    for report in fragment_message(payload, sequence):
        # On some platforms, a leading 0x00 Report-ID byte is required.
        # Try without first; add if the OS demands it.
        buf = bytes([0x00]) + report   # Report ID 0 prefix for write()
        n   = dev.write(buf)
        if n < 0:
            print(f"  [ERROR] write() returned {n}")
            dev.close()
            sys.exit(1)

    # ── Receive and reassemble the response ───────────────────────────────
    print("Waiting for response (timeout 5 s) …")
    dev.set_nonblocking(0)   # blocking mode
    asm  = Reassembler()
    msg  = None
    deadline = time.time() + 5.0

    while time.time() < deadline:
        # read() returns Report-ID byte if present; strip any leading 0x00.
        raw = dev.read(HID_REPORT_SIZE + 1, timeout_ms=500)
        if not raw:
            continue
        # Strip a leading Report-ID byte of 0 if the OS prepends one.
        if len(raw) == HID_REPORT_SIZE + 1 and raw[0] == 0x00:
            raw = raw[1:]
        if len(raw) != HID_REPORT_SIZE:
            print(f"  [WARN] unexpected report length {len(raw)}, skipping")
            continue

        hdr, _ = unpack_report(raw)
        print(f"  RX fragment  seq={hdr['sequence']}  frag={hdr['fragment']}"
              f"  flags=0x{hdr['flags']:02X}  payload_len={hdr['payload_length']}")

        msg = asm.feed(raw)
        if msg is not None:
            break

    dev.close()

    if msg is None:
        print("\nERROR: timed out waiting for a complete response.")
        sys.exit(1)

    print(f"\nReassembled response: {len(msg)} bytes")

    if args.raw:
        print("Raw bytes:", msg.hex())
        return

    print("Decoded RESP_CODE_DEVICE_INFO:")
    decode_device_info(msg)


def main():
    ap = argparse.ArgumentParser(
        description="MeshCore USB HID Companion transport test utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = ap.add_subparsers(dest="cmd")

    list_p = sub.add_parser("list", help="list all HID devices")
    list_p.set_defaults(func=cmd_list)

    # Default command (no sub-command) runs the query
    ap.add_argument("--list", action="store_true",
                    help="list all HID devices and exit")
    ap.add_argument("--vid",  type=lambda x: int(x, 0), default=0,
                    metavar="0xXXXX", help="USB vendor ID")
    ap.add_argument("--pid",  type=lambda x: int(x, 0), default=0,
                    metavar="0xXXXX", help="USB product ID")
    ap.add_argument("--serial", metavar="SN",
                    help="device serial number (optional)")
    ap.add_argument("--raw",  action="store_true",
                    help="print raw response bytes instead of decoded fields")

    args = ap.parse_args()

    if args.list or (args.vid == 0 and args.pid == 0):
        cmd_list(args)
        return

    cmd_query(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
    except Exception:
        traceback.print_exc()
        sys.exit(1)
