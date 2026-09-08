"""Bound response reads even when a server keeps sending occasional bytes.

urllib's socket timeout alone resets after activity. This wraps the raw socket
file used by the standard HTTP parser, applying the remaining wall time before
each read of headers or body. TLS verification stays in HTTPSConnection.
"""
import http.client
import io
import time
import urllib.request


class _DeadlineReader(io.RawIOBase):
    def __init__(self, sock, raw, deadline):
        self.sock, self.raw, self.deadline = sock, raw, deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("The explorer response deadline expired.")
        self.sock.settimeout(remaining)
        return self.raw.readinto(buffer)

    def close(self):
        try:
            self.raw.close()
        finally:
            super().close()


class _DeadlineSocket:
    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline

    def makefile(self, mode):
        raw = self.sock.makefile(mode, buffering=0)
        return io.BufferedReader(_DeadlineReader(self.sock, raw, self.deadline))


class DeadlineHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        deadline = time.monotonic() + req.timeout

        def connection(host, **kwargs):
            result = http.client.HTTPSConnection(host, **kwargs)
            # The same wrapper also covers HTTP CONNECT proxy response headers.
            def response(sock, *args, **response_kwargs):
                return http.client.HTTPResponse(_DeadlineSocket(sock, deadline), *args, **response_kwargs)
            result.response_class = response
            return result

        return self.do_open(connection, req, context=self._context)
