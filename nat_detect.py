#!/usr/bin/env python3
"""NAT behavior discovery per RFC 4787 / RFC 5780 (UDP, IPv4, standard library only).

Usage: python3 nat_detect.py [host[:port]]

The STUN server must support RFC 5780 (OTHER-ADDRESS and CHANGE-REQUEST).
"""
import os
import socket
import struct
import sys
import time

MAGIC = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ATTR_MAPPED = 0x0001
ATTR_CHANGE_REQUEST = 0x0003
ATTR_CHANGED_ADDRESS = 0x0005  # RFC 3489 name for OTHER-ADDRESS
ATTR_XOR_MAPPED = 0x0020
ATTR_OTHER_ADDRESS = 0x802C
FLAG_CHANGE_IP = 0x04
FLAG_CHANGE_PORT = 0x02

EI = "Endpoint-Independent"
AD = "Address-Dependent"
APD = "Address and Port-Dependent"

DEFAULT_SERVER = "stunserver2025.stunprotocol.org:3478"


def parse_addr(val, xor):
    """Decode an IPv4 (XOR-)MAPPED-ADDRESS style value into (ip, port)."""
    if len(val) < 8 or val[1] != 1:
        return None
    port = struct.unpack("!H", val[2:4])[0]
    ip = struct.unpack("!I", val[4:8])[0]
    if xor:
        port ^= MAGIC >> 16
        ip ^= MAGIC
    return socket.inet_ntoa(struct.pack("!I", ip)), port


def parse_reply(data, txid):
    """Return (mapped, other) from a Binding Success Response, or None."""
    if len(data) < 20:
        return None
    mtype, mlen, cookie = struct.unpack("!HHI", data[:8])
    if mtype != BINDING_SUCCESS or cookie != MAGIC or data[8:20] != txid:
        return None
    xor_mapped = plain_mapped = other = None
    pos, end = 20, min(20 + mlen, len(data))
    while pos + 4 <= end:
        atype, alen = struct.unpack("!HH", data[pos:pos + 4])
        if pos + 4 + alen > end:
            break
        val = data[pos + 4:pos + 4 + alen]
        if atype == ATTR_XOR_MAPPED:
            xor_mapped = parse_addr(val, True)
        elif atype == ATTR_MAPPED:
            plain_mapped = parse_addr(val, False)
        elif atype in (ATTR_OTHER_ADDRESS, ATTR_CHANGED_ADDRESS):
            other = parse_addr(val, False)
        pos += 4 + ((alen + 3) & ~3)  # attributes are padded to 4 bytes
    mapped = xor_mapped or plain_mapped
    return (mapped, other) if mapped else None


def transact(sock, dest, flags=0, tries=3):
    """Send a Binding Request and wait for a matching reply (1 s per try)."""
    txid = os.urandom(12)
    attrs = struct.pack("!HHI", ATTR_CHANGE_REQUEST, 4, flags) if flags else b""
    req = struct.pack("!HHI", BINDING_REQUEST, len(attrs), MAGIC) + txid + attrs
    for _ in range(tries):
        sock.sendto(req, dest)
        deadline = time.monotonic() + 1.0
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            sock.settimeout(left)
            try:
                data, _ = sock.recvfrom(2048)
            except socket.timeout:
                break
            reply = parse_reply(data, txid)
            if reply:
                return reply
    return None


def local_ip(server):
    """Local IPv4 address the OS would use to reach the server."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(server)
        return s.getsockname()[0]


def detect_mapping(sock, server, mapped1, other):
    """RFC 5780 section 4.3. Uses one socket for every probe."""
    r2 = transact(sock, (other[0], server[1]))  # other IP, primary port
    if r2 is None:
        return None
    if r2[0] == mapped1:
        return EI
    r3 = transact(sock, other)  # other IP, other port
    if r3 is None:
        return None
    return AD if r3[0] == r2[0] else APD


def detect_filtering(server):
    """RFC 5780 section 4.4. Uses a fresh socket so earlier probes cannot
    have opened the filter toward the server's alternate address."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("", 0))
        if transact(s, server) is None:
            return None
        if transact(s, server, FLAG_CHANGE_IP | FLAG_CHANGE_PORT, tries=2):
            return EI
        if transact(s, server, FLAG_CHANGE_PORT, tries=2):
            return AD
        return APD


def legacy_name(mapping, filtering):
    if mapping is None or filtering is None:
        return "unknown"
    if mapping != EI:
        return "symmetric"
    return {EI: "full cone", AD: "restricted cone", APD: "port-restricted cone"}[filtering]


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SERVER
    host, _, port = arg.rpartition(":")
    if not host:
        host, port = arg, "3478"
    try:
        server = (socket.gethostbyname(host), int(port))
    except (OSError, ValueError) as e:
        sys.exit(f"cannot resolve {arg}: {e}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))

    first = transact(sock, server)
    if first is None:
        sys.exit(f"no STUN reply from {server[0]}:{server[1]}")
    mapped1, other = first
    print(f"Server:  {server[0]}:{server[1]}")
    print(f"Mapped:  {mapped1[0]}:{mapped1[1]}")
    if mapped1 == (local_ip(server), sock.getsockname()[1]):
        print("Note:    mapped address equals local address, so no NAT was detected.")
    if other is None:
        sys.exit("The server did not send OTHER-ADDRESS, so it does not support RFC 5780. "
                 "Use a server that does (for example coturn or stunserver2025.stunprotocol.org).")

    mapping = detect_mapping(sock, server, mapped1, other)
    filtering = detect_filtering(server)
    print(f"Mapping behavior:   {mapping or 'unknown (no reply from alternate address)'}")
    print(f"Filtering behavior: {filtering or 'unknown (no reply)'}")
    print(f"Legacy name (approximate): {legacy_name(mapping, filtering)}")


if __name__ == "__main__":
    main()
