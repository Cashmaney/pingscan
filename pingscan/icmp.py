import struct
import collections
from cy_src.c_icmp import build as cbuild

ICMPHeader = collections.namedtuple('ICMPHeader', 'type code checksum')

ICMP_ECHO_REPLY = 0
ICMP_OFFSET_V4 = 20
MSG_ID_OFFSET_V4 = 24
SRC_IP_OFFSET_v4 = 12
ICMP_NETWORK_UNREACH = 3
MAX_SEQUENCE = 65535
IPv4 = 0
IPv6 = 1

msg_id_offset = MSG_ID_OFFSET_V4
offset = ICMP_OFFSET_V4
offset_src_ip = SRC_IP_OFFSET_v4


def parse(packet: bytes) -> ICMPHeader:
    icmp_header = packet[ICMP_OFFSET_V4: ICMP_OFFSET_V4 + 8]
    type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
    return ICMPHeader(type, code, checksum)


def build(seq=1, msg_id=1) -> bytes:
    packet = cbuild(seq, msg_id)
    return bytes(packet)


def msg_id_match(packet: memoryview, msg_id=1, pos:int = 0, family: int=IPv4) -> int:
    # if family == IPv4:
    # print(f"{packet[msg_id_offset + pos]}")
    # icmp type
    return int().from_bytes(packet[msg_id_offset + pos:msg_id_offset + 2 + pos], byteorder='little') == msg_id


def src_ip_from_packet(packet: memoryview, pos:int = 0, family: int=IPv4) -> int:
    # if family == IPv4:

    resp_ip = int().from_bytes(packet[offset_src_ip + pos:offset_src_ip + 4 + pos], byteorder='big')
    return resp_ip


def is_icmp_reply(packet: memoryview, pos: int = 0, family: int=IPv4) -> bool:
    # if family == IPv4:

    # icmp type
    return packet[offset + pos] == ICMP_ECHO_REPLY
