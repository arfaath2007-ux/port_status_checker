"""
Unit tests for port_checker.py
Verifies open, closed, filtered, and invalid port behaviors using local sockets.
"""

import socket
import unittest
import threading
from port_checker import check_port, get_service_name


class TestPortChecker(unittest.TestCase):
    def test_service_name_lookup(self):
        self.assertIn("HTTP", get_service_name(80))
        self.assertIn("HTTPS", get_service_name(443))
        self.assertIn("SSH", get_service_name(22))

    def test_open_port(self):
        # Bind a temporary local server to an available port
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        port = server_sock.getsockname()[1]
        server_sock.listen(1)

        def accept_conn():
            try:
                conn, _ = server_sock.accept()
                conn.close()
            except Exception:
                pass

        thread = threading.Thread(target=accept_conn)
        thread.daemon = True
        thread.start()

        try:
            status, explanation, elapsed_ms = check_port("127.0.0.1", port, timeout=1.0)
            self.assertEqual(status, "OPEN")
            self.assertIsNotNone(elapsed_ms)
        finally:
            server_sock.close()

    def test_inactive_port(self):
        # Bind and close immediately to get an inactive port
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_sock.bind(("127.0.0.1", 0))
        port = temp_sock.getsockname()[1]
        temp_sock.close()

        status, explanation, elapsed_ms = check_port("127.0.0.1", port, timeout=0.5)
        # On modern OSes, inactive ports may be CLOSED (RST) or FILTERED (stealth drop)
        self.assertIn(status, ("CLOSED", "FILTERED"))

    def test_invalid_hostname(self):
        status, explanation, elapsed_ms = check_port("invalid.domain.that.does.not.exist.local", 80, timeout=1.0)
        self.assertEqual(status, "ERROR")
        self.assertIn("Could not resolve host", explanation)


if __name__ == "__main__":
    unittest.main()
