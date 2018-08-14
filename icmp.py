import struct
import collections


ICMPHeader = collections.namedtuple('ICMPHeader', 'type code checksum')

icmp_reply = 0x0

seq = 1


def two_byte_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = two_byte_add(s, w)
    return ~s & 0xffff


def parse(packet: bytes) -> ICMPHeader:
    icmp_header = packet[20:28]
    type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
    return ICMPHeader(type, code, checksum)


def build() -> bytes:
    global seq

    type = '\x08'
    code = '\x00'
    csum = '\x00\x00'
    msg_id = '\x00\x01'
    seq = '\x00\x01'#bytes(seq + 1 % 65536)
    data = 'abcdefghijklmnopqrstuvwabcdefg'

    msg = type + code + csum + msg_id + seq + data

    csum = checksum(msg)
    header = struct.pack('bbH', 8, 0, csum)
    header = header + bytes(msg_id.encode()) + bytes(seq.encode())
    packet = header + bytes(data.encode())
    return packet
