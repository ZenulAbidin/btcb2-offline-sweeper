"""Real local socket-pair regressions for slow-drip headers and bodies."""
import http.client
import socket
import threading
import time
import unittest

from btcb2_tui.http_deadline import _DeadlineSocket


class DeadlineTests(unittest.TestCase):
    def _drip(self, header_first):
        left, right = socket.socketpair()
        finished = threading.Event()
        errors = []
        def sender():
            try:
                if header_first:
                    right.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                    payload = b"x" * 100
                else:
                    payload = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                for byte in payload:
                    if finished.wait(.025):
                        break
                    right.sendall(bytes([byte]))
            except OSError:
                pass
        worker = threading.Thread(target=sender)
        worker.start()
        began = time.monotonic()
        response = http.client.HTTPResponse(_DeadlineSocket(left, began + .15))
        try:
            with self.assertRaises((TimeoutError, OSError)):
                response.begin()
                response.read()
            self.assertLess(time.monotonic() - began, 1.5)
        finally:
            finished.set()
            response.close()
            left.close()
            right.close()
            worker.join(timeout=2)

    def test_slow_headers_cannot_reset_deadline_forever(self):
        self._drip(False)

    def test_slow_body_cannot_reset_deadline_forever(self):
        self._drip(True)

    def test_normal_response_remains_readable_after_connection_closes_its_handle(self):
        left, right = socket.socketpair()
        right.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")
        response = http.client.HTTPResponse(_DeadlineSocket(left, time.monotonic() + 1))
        try:
            response.begin()
            left.close()  # urllib relinquishes its handle before the body is consumed.
            right.sendall(b"ok")  # Ensure the body is not already in the parser's buffer.
            self.assertEqual(response.read(), b"ok")
        finally:
            response.close()
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
