import time
import logging
from netscan import netscan


def main():
    logging.basicConfig(level=logging.CRITICAL)

    start_time = time.time()

    ip = '172.16.0.0'
    network = '255.255.255.0'

    res = netscan.scan(ip, network)
    print(f"[{int((time.time() - start_time) * 1000)}ms] {len(res)}")


if __name__ == "__main__":
    main()

