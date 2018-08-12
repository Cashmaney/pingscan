import struct
import collections


ICMPHeader = collections.namedtuple('ICMPHeader', 'type code checksum')

icmp_reply = 0x8

def parse(packet: bytes) -> ICMPHeader:
    icmp_header = packet[20:28]
    type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
    return ICMPHeader(type, code, checksum)