import asyncio
import logging
import time
import multiprocessing
import random
from typing import Callable, Union

from netscan import icmp
from netscan.icmp import build
from netscan.utils import split_networks, _generate_ips, _send, get_eventloop, get_socket, host_count


logger = logging.getLogger(__name__)

default_timeout = 0.1
ICMP_MAX_SIZE = 150
sender_id = 1
seq = 1


# timeout > 0 just so everything won't timeout immediately
def scan(ip: str, network: str='255.255.255.255', *, timeout: float=default_timeout,
         workers: int=4, loop: asyncio.AbstractEventLoop):
    """ main method for ping scanning """
    # we might be provided with an event loop
    if loop:
        result = AsyncPinger(loop=loop).ping(ip, network, timeout, workers)

    else:
        with get_eventloop() as loop:
            result = AsyncPinger(loop=loop).ping(ip, network, timeout, workers)

    return result


class AsyncPinger:
    """
    pinger class - we're using a class here because it's the easy to store shared values and duplicate them
    """

    def __init__(self, loop: asyncio.AbstractEventLoop = asyncio.get_event_loop()) -> None:
        self.done_sending = False
        self.loop = loop
        self.timeout = 0
        self.logger = logging.getLogger(__class__.__name__)
        self.queue = asyncio.Queue()
        self.addresses = {}
        self.num_of_hosts = 0
        self.start_time = None
        self.worker_processes = 1
        self.rsock = None
        self.id = random.randint(0, 65535)  # 2 byte max value, we use this to support multithreading
        self.send_done_count = multiprocessing.Value('i', 0)

    def ping(self, ip: str, network: str = '255.255.255.255',
             timeout: float = default_timeout, workers: int = 4) -> dict:
        self.timeout = timeout
        self.worker_processes = workers

        self.num_of_hosts = host_count(ip, network)

        self.loop.call_soon(self.send, ip, network)

        tasks = list()
        with get_socket() as self.rsock:
            tasks.append(asyncio.ensure_future(self.recv()))
            tasks.append(asyncio.ensure_future(self.process()))

            self.loop.run_until_complete(asyncio.gather(*tasks))

        return self.fetch_result()

    async def process(self):
        """ responsible for removing packets from the queue and processing them. End condition is when the queue is
         empty and timeout has passed """
        while True:
            try:

                packet = await asyncio.wait_for(self.queue.get(), self.timeout / 10)

            except asyncio.TimeoutError:
                # if queue isn't empty yet we're not done
                if self.queue.empty() and self._timeout():
                    # queue empty, recv done & queue.get timeout -> processing packets is done
                    return
                continue

            self.process_packet(packet, self._process_callback)

    async def recv(self):
        """
        Async recv function. Will try to receive until the sender method is done, then will receive until timeout is done.
        Note: we're trying to receive from a raw socket, so even if we use multiple listeners they will wake on the
        same packets

        """
        # need to make the buffer big enough to guard against overflow
        bufsiz = self.num_of_hosts * ICMP_MAX_SIZE * 2
        bytebuff = bytearray(bufsiz)
        # placeholder
        pos = 0
        while True:
            try:
                memview = memoryview(bytebuff)[pos:pos + ICMP_MAX_SIZE]

                read = await asyncio.wait_for(self.loop.sock_recv_into(self.rsock, memview),
                                              self.timeout / 100)

                pos += read
                pos = pos % bufsiz

            except asyncio.TimeoutError:
                if self._timeout():
                    return
                continue

            # enqueue the received packet (parsing it will be done elsewhere)
            self.queue.put_nowait(memview)

            if self._timeout():
                return
            continue

    def _process_callback(self, ip: str):
        self.addresses.update({ip: True})

    def fetch_result(self) -> dict:
        return self.addresses

    def process_packet(self, packet: memoryview, addr_handle_callback: Callable) -> None:
        """ Checks if a packet is ICMP reply, and records the sender address if it is. We use a callback here
        for handling of ip address even though it is probably a tiny bit more overhead to make it easier to understand
        the flow of the code """
        if icmp.is_icmp_reply(packet) and icmp.msg_id_match(packet, self.id):
            resp_ip = icmp.src_ip_from_packet(packet)
            addr_handle_callback(resp_ip)

    def _done_sending(self) -> bool:
        return self.send_done_count.value == self.worker_processes

    def _timeout(self) -> bool:
        if self._done_sending():
            if not self.start_time:
                self.start_time = time.time()

            td = int((time.time() - self.start_time) * 1000)

            return td > self.timeout * 1000 * 99 / 100

    def send(self, ip: str, network: str):
        networks = split_networks(ip, network, self.worker_processes)
        for network in networks:
            process = multiprocessing.Process(target=send_multiple,
                                              args=(self.send_done_count, network[0], network[1], self.id))
            process.start()


def send_multiple(send_done_count: multiprocessing.Value, ip: str, network: str = '255.255.255.255', msg_id=1):
    """ ping all addresses given by ip/network combo

    send_done_count is used as a semaphore so we can tell if all jobs are finished. Every worker will decrease it
    by 1 when it finished

    """
    addrs = _generate_ips(ip, network)

    pkt_seq = 0
    with get_socket() as ssock:
        try:
            for addr in addrs:
                pkt_seq += 1 % icmp.MAX_SEQUENCE

                packet = build(pkt_seq, msg_id)
                _send(ssock, str(addr), packet)
        finally:
            send_done_count.value += 1
