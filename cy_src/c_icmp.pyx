from libc.string cimport memcpy

cdef short checksum(char* buffer, short length):
    """
    :param buffer:
    :param length:
    :return:
    """
    cdef unsigned short *buf = <unsigned short *>buffer
    cdef unsigned int sum=0
    cdef unsigned short result
    cdef unsigned char pos = 0
    cdef short t_length = length
    while t_length > 1:
        sum += buf[pos]
        t_length = t_length - 2
        pos = pos + 1
    if t_length == 1:
        sum += buffer[length - 1]
    sum = (sum >> 16) + (sum & 0xFFFF)
    sum += (sum >> 16)
    result = ~sum
    return result

def build(unsigned short seq, unsigned short msg_id):

    cdef char ICMP_ECHO_REQUEST = 8
    cdef int code = 0
    cdef unsigned short csum = 0

    cdef char packet[18]
    cdef char payload[10]

    payload = <char*>'abcdefghij'

    memcpy(&packet[0], <char *>&ICMP_ECHO_REQUEST, 1)
    memcpy(&packet[1], <char *>&code, 1)
    memcpy(&packet[2], <char *>&csum, 2)
    memcpy(&packet[4], <char *>&msg_id, 2)
    memcpy(&packet[6], <char *>&seq, 2)
    memcpy(&packet[8], <char *>&payload, 10)
    csum = checksum(&packet[0], 18)
    memcpy(&packet[2], <char *>&csum, 2)
    result = ([ d for d in packet[:18] ])
    return result
