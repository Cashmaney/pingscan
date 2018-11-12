import time
import logging
import pingscan


def main():
    logging.basicConfig(level=logging.CRITICAL)

    start_time = time.time()

    ips = ['127.0.0.0/24', '127.0.1.1', '127.0.1.2', '127.0.1.3', '127.0.1.4']
    res = pingscan.scan(ips, timeout=1.5)
    print(f"[{int((time.time() - start_time) * 1000)}ms] {len(res)}\n{res}")


if __name__ == "__main__":
    main()
