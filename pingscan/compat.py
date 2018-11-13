import asyncio
import sys
import types


def loop_compat(self: asyncio.AbstractEventLoop):
    """ patch a < 3.7 event loop with the sock_recv_into methods """
    if sys.version_info < (3, 7):
        async def sock_recv_into(self, sock, buf):
            """Receive data from the socket.

            The received data is written into *buf* (a writable buffer).
            The return value is the number of bytes written.
            """
            if self._debug and sock.gettimeout() != 0:
                raise ValueError("the socket must be non-blocking")
            fut = self.create_future()
            self._sock_recv_into(fut, None, sock, buf)
            return await fut

        def _sock_recv_into(self, fut, registered_fd, sock, buf):
            # _sock_recv_into() can add itself as an I/O callback if the operation
            # can't be done immediately. Don't use it directly, call
            # sock_recv_into().
            if registered_fd is not None:
                # Remove the callback early.  It should be rare that the
                # selector says the FD is ready but the call still returns
                # EAGAIN, and I am willing to take a hit in that case in
                # order to simplify the common case.
                self.remove_reader(registered_fd)
            if fut.cancelled():
                return
            try:
                nbytes = sock.recv_into(buf)
            except (BlockingIOError, InterruptedError):
                fd = sock.fileno()
                self.add_reader(fd, self._sock_recv_into, fut, fd, sock, buf)
            except Exception as exc:
                fut.set_exception(exc)
            else:
                fut.set_result(nbytes)
        self.sock_recv_into = types.MethodType(sock_recv_into, self)
        self._sock_recv_into = types.MethodType(_sock_recv_into, self)

