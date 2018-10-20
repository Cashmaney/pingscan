import time
import logging
import aio_ping_scan

def main():
    logging.basicConfig(level=logging.DEBUG)
    start_time = time.time()
    addrs = aio_ping_scan.mp_ping('8.8.0.0', '255.255.0.0', timeout=8, workers=4)
    print(f"[{int((time.time() - start_time) * 1000)}ms] {addrs}")


if __name__ == "__main__":
    main()
