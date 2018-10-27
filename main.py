import time
import logging
import netscan
from multiping import multi_ping

import socket
from utils import ip_mask_to_list


def test_multiping():
    start_time = time.time()
    addrs = ip_mask_to_list('172.16.0.0', '255.255.255.0')
    str_addrs = []
    for addr in addrs:
        str_addrs.append(str(addr))
    try:
        result = multi_ping(str_addrs,
                            timeout=0.1, retry=0, ignore_lookup_errors=True)
        print(f"[{int((time.time() - start_time) * 1000)}ms] {len(result[0]), result[0]}")
    except socket.timeout as e:
        print(f'{e}')


def main():
    logging.basicConfig(level=logging.CRITICAL)

    test_multiping()

    start_time = time.time()

    ip = '172.16.0.0'
    network = '255.255.255.0'

    res = netscan.ping(ip, network)
    print(f"[{int((time.time() - start_time) * 1000)}ms] {len(res)}")


if __name__ == "__main__":
    main()

