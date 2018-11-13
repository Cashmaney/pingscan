import asyncio
import logging
import time
import multiprocessing
import random
import ipaddress
import sys
from collections import defaultdict
from typing import Callable, Union, List, Dict, Tuple

from pingscan import icmp
from pingscan.icmp import build
from pingscan.utils import split_networks, _generate_ips, _send, host_count, split_addrs
from pingscan.resources import get_eventloop, get_socket


logger = logging.getLogger(__name__)

default_processes = 4
default_timeout = 1
ICMP_MAX_SIZE = 150
sender_id = 1
seq = 1


def scan(ip: Union[List, str], network: str = '255.255.255.255', *, timeout: float = default_timeout,
         workers: int = default_processes, loop: asyncio.AbstractEventLoop = None) -> List[str]:
    """ main method for ping scanning IPv4 addresses

    Usage: pingscan.scan(['192.168.0.0/24', '192.168.1.0/24','192.168.2.1']) OR
           pingscan.scan('192.168.0.0', '255.255.255.0')

    Additional parameters:
        timeout: how long to wait for answers to respond. Starts counting from the end of the send
        workers: number of processes to use for sending
        loop: if you want to manage the asyncio loop yourself

    :returns a list of all addresses that answered
    """

    tasks = _parse_input(ip, network, workers)

    _check_working()

    # make sure tasks isn't some strange length for some reason
    assert workers == len(tasks)

    # we might be provided with an event loop
    if loop:
        result = AsyncPinger(loop=loop).ping(tasks, timeout, workers)

    else:
        with get_eventloop() as event_loop:
            result = AsyncPinger(loop=event_loop).ping(tasks, timeout, workers)

    return result


def _check_working():
    try:
        with get_socket() as ssock:
            packet = build(1, 1)
            _send(ssock, '127.0.0.1', packet)
    except PermissionError as e:
        sys.tracebacklimit = 0  # might not work for python 3.6.1
        e.strerror = "Are you root, or do you have the required capabilities?"
        e.__traceback__ = None
        raise e


def _parse_input(ip: Union[List, str], network: str = '255.255.255.255', workers: int = default_processes):
    """ convert the ip, network into a structure containing address/masks """
    # if this is list split it into worker tasks
    if isinstance(ip, list):
        tasks = split_addrs(ip, workers=workers)
    else:
        tasks = defaultdict(list)
        # split the subnet into X subnets and append
        for count, net in enumerate(split_networks(ip, network, partitions=workers)):
            tasks[count].append(tuple(net))
        tasks = dict(tasks)
    return tasks


class AsyncPinger:
    """
    pinger class - we're using a class here because it's the easy to store shared values and duplicate them
    """

    def __init__(self, loop: asyncio.AbstractEventLoop = asyncio.get_event_loop()) -> None:
        self.done_sending = False
        self.loop = loop
        self.timeout = 0
        self.logger = logging.getLogger(self.__class__.__name__)
        self.queue = asyncio.Queue()
        self.addresses = []
        self.num_of_hosts = 0
        self.start_time = None
        self.worker_processes = 1
        self.rsock = None
        self.id = random.randint(0, 65535)  # 2 byte max value, we use this to support multithreading
        self.send_done_count = multiprocessing.Value('i', 0)

    def ping(self, worker_tasks: Union[Dict[int, List[Tuple[str, str]]]],
             timeout: float = default_timeout, workers: int = default_processes) -> list:
        """
        Usage: ping('192.168.0.0', '255.255.255.0') OR
               ping({0: [('192.168.0.0', '255.255.255.192')],
                    {1: [('192.168.0.64', '255.255.255.192')],
                    ....
                    }

        Note that we already split the addresses when we called the top level method - this is already internals
        so I don't mind the methods being less user-friendly
        """
        self.timeout = timeout
        self.worker_processes = workers

        for task in worker_tasks.values():
            for ip, net in task:
                self.num_of_hosts += host_count(ip, net)

        logger.debug(f'total number of hosts to ping: {self.num_of_hosts}')
        self.loop.call_soon(self.send, worker_tasks)

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
        Async recv function. Will try to receive until the sender method is done, then run until timeout is done.
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
        self.addresses.append(ip)

    def fetch_result(self) -> list:
        return [str(ipaddress.IPv4Address(addr)) for addr in self.addresses]

    def process_packet(self, packet: memoryview, store_address_callback: Callable) -> None:
        """ Checks if a packet is ICMP reply, and records the sender address if it is. We use a callback here
        for storing the ip address even though it is probably a tiny bit more overhead to make it easier to understand
        the flow of the code """
        if icmp.is_icmp_reply(packet) and icmp.msg_id_match(packet, self.id):
            resp_ip = icmp.src_ip_from_packet(packet)
            store_address_callback(resp_ip)

    def _done_sending(self) -> bool:
        return self.send_done_count.value == self.worker_processes

    def _timeout(self) -> bool:
        if self._done_sending():
            if not self.start_time:
                self.start_time = time.time()

            td = int((time.time() - self.start_time) * 1000)

            return td > self.timeout * 1000 * 99 / 100
        return False

    def send(self, all_tasks: Dict[int, List[Tuple[str, str]]]):
        # note that len(all_tasks) == len(workers)
        for task in all_tasks.values():
            process = multiprocessing.Process(target=send_multiple,
                                              args=(self.send_done_count, task, self.id))
            process.start()


def send_multiple(send_done_count: multiprocessing.Value, ips: List[Tuple[str, str]], msg_id=1):
    """ ping all addresses given by ip/network combo

    send_done_count is used as a semaphore so we can tell if all jobs are finished. Every worker will decrease it
    by 1 when it finished

    """
    with get_socket() as ssock:
        try:
            for ip, network in ips:
                addrs = _generate_ips(ip, network)

                pkt_seq = 0
                for addr in addrs:
                    pkt_seq += 1 % icmp.MAX_SEQUENCE

                    packet = build(pkt_seq, msg_id)
                    _send(ssock, str(addr), packet)
        finally:
            send_done_count.value += 1
