#!/usr/bin/env python3
import struct
import time

# -------------------------------
# Helpers
# -------------------------------

def ip_checksum(data: bytes) -> int:
    """Compute IPv4 header checksum."""
    if len(data) % 2 == 1:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


# -------------------------------
# ITCH-like message builder
# -------------------------------

def build_itch_message(msg_type: bytes, seq: int, price: int, qty: int) -> bytes:
    """
    Build a *simplified* ITCH-like message:

    [0-1]  uint16  message_length (including msg_type + body)
    [2]    char    message_type (e.g. b'A', b'E', ...)
    [3-6]  uint32  sequence_number
    [7-10] uint32  price (e.g. in ticks)
    [11-14]uint32  quantity
    """
    body = struct.pack('>III', seq, price, qty)
    length = 1 + len(body)  # msg_type + body
    return struct.pack('>H', length) + msg_type + body


# -------------------------------
# Ethernet + IPv4 + UDP builder
# -------------------------------

def build_udp_packet(payload: bytes,
                     src_port: int = 4000,
                     dst_port: int = 4001,
                     src_ip=(192, 168, 0, 1),
                     dst_ip=(192, 168, 0, 2),
                     src_mac=b'\x06\x05\x04\x03\x02\x01',
                     dst_mac=b'\x01\x02\x03\x04\x05\x06') -> bytes:
    # Ethernet header
    eth_type = 0x0800  # IPv4
    eth_hdr = dst_mac + src_mac + struct.pack('!H', eth_type)

    # IPv4 header
    version_ihl = (4 << 4) | 5  # version=4, IHL=5 (20 bytes)
    tos = 0
    total_length = 20 + 8 + len(payload)  # IP header + UDP header + payload
    identification = 0
    flags_fragment = 0
    ttl = 64
    proto = 17  # UDP
    hdr_checksum = 0
    src_ip_bytes = bytes(src_ip)
    dst_ip_bytes = bytes(dst_ip)

    ip_hdr_wo_checksum = struct.pack(
        '!BBHHHBBH4s4s',
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        proto,
        hdr_checksum,
        src_ip_bytes,
        dst_ip_bytes
    )

    hdr_checksum = ip_checksum(ip_hdr_wo_checksum)

    ip_hdr = struct.pack(
        '!BBHHHBBH4s4s',
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        proto,
        hdr_checksum,
        src_ip_bytes,
        dst_ip_bytes
    )

    # UDP header (checksum set to 0 = optional for IPv4)
    udp_len = 8 + len(payload)
    udp_checksum = 0
    udp_hdr = struct.pack('!HHHH', src_port, dst_port, udp_len, udp_checksum)

    return eth_hdr + ip_hdr + udp_hdr + payload


# -------------------------------
# PCAP writer
# -------------------------------

def write_pcap(filename: str, frames: list[bytes]) -> None:
    """
    Write a list of raw Ethernet frames to a pcap file.
    """
    # PCAP global header (little-endian, Ethernet link type)
    magic_number = 0xa1b2c3d4  # Wireshark will treat this as little-endian
    version_major = 2
    version_minor = 4
    thiszone = 0
    sigfigs = 0
    snaplen = 65535
    network = 1  # LINKTYPE_ETHERNET

    global_hdr = struct.pack(
        '<IHHIIII',
        magic_number,
        version_major,
        version_minor,
        thiszone,
        sigfigs,
        snaplen,
        network
    )

    with open(filename, 'wb') as f:
        f.write(global_hdr)

        ts_base = int(time.time())
        for i, frame in enumerate(frames):
            ts_sec = ts_base
            ts_usec = i * 1000  # each packet 1 ms apart
            incl_len = len(frame)
            orig_len = len(frame)

            pkt_hdr = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
            f.write(pkt_hdr)
            f.write(frame)


# -------------------------------
# Main: generate fake ITCH traffic
# -------------------------------

def main():
    frames = []
    seq = 1

    num_packets = 10      # number of UDP packets
    msgs_per_packet = 5   # how many ITCH messages per UDP payload

    for packet_idx in range(num_packets):
        msgs = []
        for m in range(msgs_per_packet):
            # Alternate between 'A' (add) and 'E' (execute) for fun
            msg_type = b'A' if m % 2 == 0 else b'E'
            price = 10000 + packet_idx * 10 + m  # fake price (e.g. 100.00)
            qty = 100 + m                         # fake quantity

            msgs.append(build_itch_message(msg_type, seq, price, qty))
            seq += 1

        payload = b''.join(msgs)
        frame = build_udp_packet(payload)
        frames.append(frame)

    out_file = 'fake_itch.pcap'
    write_pcap(out_file, frames)
    print(f'Wrote {len(frames)} packets to {out_file}')


if __name__ == '__main__':
    main()

