import struct
import collections
from cy_src.c_icmp import build as cbuild
# #import cy_src.helloworld.build

ICMPHeader = collections.namedtuple('ICMPHeader', 'type code checksum')


def parse(packet: bytes) -> ICMPHeader:
    icmp_header = packet[20:28]
    type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
    return ICMPHeader(type, code, checksum)


def build(seq=1, msg_id=1) -> bytes:
    packet = cbuild(seq, msg_id)
    return bytes(packet)
