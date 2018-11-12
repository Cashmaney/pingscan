import asyncio
import socket
from contextlib import contextmanager, suppress


SOCK_BUFSIZ = 134217728


def _create_socket():
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUFSIZ)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUFSIZ)
    sock.setblocking(False)
    return sock


@contextmanager
def get_eventloop():
    # Code to acquire resource:
    _loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_loop)
    yield _loop

    # Code to release resource:
    pending = asyncio.Task.all_tasks()
    for task in pending:
        task.cancel()
        # Now we should await task to execute it's cancellation.
        # Cancelled task raises asyncio.CancelledError that we can suppress:
        with suppress(asyncio.CancelledError):
            _loop.run_until_complete(task)
    _loop.close()


@contextmanager
def get_socket():
    # Code to acquire resource, e.g.:
    _socket = _create_socket()
    try:
        yield _socket
    finally:
        # Code to release resource, e.g.:
        _socket.close()