"""
test_sslcheck.py — hermetic tests for the sslcheck offline engine.

Hermetic (no internet, no /etc/hosts edits): a local self-signed TLS server,
a firewall-style RST listener, and a real HTTP CONNECT proxy (with optional
Basic auth) are started per class.  Run from the repo root:

    python3 test_sslcheck.py -v

Covers:
  * _normalise_target — http:// URLs now target 443; explicit ports kept
  * _proxy_for / _host_in_no_proxy — env parsing, no_proxy, loopback guard
  * blocked direct path → clear diagnosis + hint, protocols honest N/T
  * blocked direct + proxy configured → full openssl result via CONNECT
  * blocked direct + AUTHENTICATING proxy → python-ssl rescue engine
  * plaintext service / dead port → precise, actionable errors
  * direct local TLS → unchanged behaviour (grade T, protocols, ciphers)
"""

import base64
import os
import re
import select
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sslcheck  # noqa: E402

TMP = tempfile.mkdtemp(prefix="sslchk_")


# --------------------------------------------------------------------------
# local pieces
# --------------------------------------------------------------------------

def _mkcert():
    crt, key = os.path.join(TMP, "s.crt"), os.path.join(TMP, "s.key")
    if not os.path.isfile(crt):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-nodes", "-keyout", key, "-out", crt, "-days", "5",
                        "-subj", "/CN=localhost", "-addext",
                        "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                       check=True, capture_output=True)
    return crt, key


def start_tls():
    crt, key = _mkcert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(64)

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return

            def one(c=c):
                try:
                    t = ctx.wrap_socket(c, server_side=True)
                    t.settimeout(3)
                    try:
                        data = t.recv(2048)
                        if data.startswith(b"GET"):
                            t.sendall(b"HTTP/1.1 200 OK\r\n"
                                      b"Strict-Transport-Security: "
                                      b"max-age=31536000\r\n"
                                      b"Content-Length: 2\r\n"
                                      b"Connection: close\r\n\r\nok")
                    except Exception:
                        pass
                    t.close()
                except Exception:
                    try:
                        c.close()
                    except OSError:
                        pass
            threading.Thread(target=one, daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1], srv.close


def start_rst():
    """Accept TCP, reset on the first client bytes — a firewall in miniature."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(64)

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return

            def one(c=c):
                try:
                    c.recv(1)
                    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                 struct.pack("ii", 1, 0))
                finally:
                    c.close()
            threading.Thread(target=one, daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1], srv.close


def start_proxy(portmap=None, auth=None):
    """HTTP CONNECT proxy; portmap {(host, port): (h2, p2)} simulates 'the
    proxy can reach a destination the direct path cannot'."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(64)
    hits = []

    def pipe(a, b):
        try:
            while True:
                r, _, _ = select.select([a, b], [], [], 30)
                if not r:
                    return
                for s in r:
                    d = s.recv(65536)
                    if not d:
                        return
                    (b if s is a else a).sendall(d)
        except OSError:
            pass

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return

            def one(c=c):
                try:
                    c.settimeout(10)
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        d = c.recv(4096)
                        if not d:
                            c.close()
                            return
                        buf += d
                    head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
                    line = head.split("\r\n")[0]
                    if not line.startswith("CONNECT "):
                        c.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                        c.close()
                        return
                    if auth:
                        want = ("Basic "
                                + base64.b64encode(auth.encode()).decode())
                        got = [ln.split(":", 1)[1].strip()
                               for ln in head.split("\r\n")
                               if ln.lower().startswith("proxy-authorization:")]
                        if not got or got[0] != want:
                            c.sendall(
                                b"HTTP/1.1 407 Proxy Authentication Required"
                                b"\r\nProxy-Authenticate: Basic realm=\"t\""
                                b"\r\n\r\n")
                            c.close()
                            return
                    hp = line.split()[1]
                    h, _, p = hp.rpartition(":")
                    h, p = h.strip("[]"), int(p)
                    h, p = (portmap or {}).get((h, p), (h, p))
                    try:
                        up = socket.create_connection((h, p), timeout=8)
                    except OSError:
                        c.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        c.close()
                        return
                    hits.append(hp)
                    c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    c.settimeout(None)
                    pipe(c, up)
                    up.close()
                    c.close()
                except Exception:
                    try:
                        c.close()
                    except OSError:
                        pass
            threading.Thread(target=one, daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1], hits, srv.close


def _clearenv():
    for k in ("SSLCHECK_PROXY", "https_proxy", "HTTPS_PROXY", "http_proxy",
              "HTTP_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"):
        os.environ.pop(k, None)


# --------------------------------------------------------------------------
# unit — target normalisation + proxy discovery
# --------------------------------------------------------------------------

class TestNormaliseTarget(unittest.TestCase):
    def test_http_url_targets_443(self):
        self.assertEqual(sslcheck._normalise_target("http://example.com/any/path"),
                         ("example.com", 443))

    def test_https_url_targets_443(self):
        self.assertEqual(sslcheck._normalise_target("https://example.com/any/path"),
                         ("example.com", 443))

    def test_explicit_ports_kept(self):
        self.assertEqual(sslcheck._normalise_target("http://h.example:8080/x"),
                         ("h.example", 8080))
        self.assertEqual(sslcheck._normalise_target("h.example:8443"),
                         ("h.example", 8443))
        self.assertEqual(sslcheck._normalise_target("[::1]:9443"),
                         ("::1", 9443))

    def test_junk_port_and_userinfo(self):
        self.assertEqual(sslcheck._normalise_target("https://host:junk/"),
                         ("host", 443))
        self.assertEqual(sslcheck._normalise_target("user@host.example/p"),
                         ("host.example", 443))


class TestProxyDiscovery(unittest.TestCase):
    def setUp(self):
        _clearenv()

    def tearDown(self):
        _clearenv()

    def test_env_order_and_auth(self):
        os.environ["https_proxy"] = "http://u:p@corp-proxy:3128"
        p = sslcheck._proxy_for("example.com")
        self.assertEqual((p["host"], p["port"], p["auth"]),
                         ("corp-proxy", 3128, "u:p"))
        os.environ["SSLCHECK_PROXY"] = "override:8080"      # wins, schemeless ok
        p = sslcheck._proxy_for("example.com")
        self.assertEqual((p["host"], p["port"]), ("override", 8080))

    def test_no_proxy_and_loopback_never_proxied(self):
        os.environ["https_proxy"] = "http://corp-proxy:3128"
        os.environ["no_proxy"] = "internal.corp,10.0.0.5,.lab.local"
        for h in ("internal.corp", "sub.internal.corp", "x.lab.local",
                  "10.0.0.5", "localhost", "127.0.0.1", "127.0.0.9"):
            self.assertIsNone(sslcheck._proxy_for(h), h)
        self.assertIsNotNone(sslcheck._proxy_for("example.com"))

    def test_no_proxy_star(self):
        os.environ["https_proxy"] = "http://corp-proxy:3128"
        os.environ["NO_PROXY"] = "*"
        self.assertIsNone(sslcheck._proxy_for("example.com"))


# --------------------------------------------------------------------------
# integration — the customer failure, diagnosed and then fixed
# --------------------------------------------------------------------------

class TestBlockedDirect(unittest.TestCase):
    """Firewall RST on the direct path (the exact production failure)."""

    @classmethod
    def setUpClass(cls):
        _clearenv()
        cls.rst, cls._c1 = start_rst()
        cls.tls, cls._c2 = start_tls()

    @classmethod
    def tearDownClass(cls):
        cls._c1()
        cls._c2()
        _clearenv()

    def test_no_proxy_gives_diagnosis_not_false_protocols(self):
        r = sslcheck.offline_check("127.0.0.1", self.rst)
        self.assertEqual(r["grade"], "-")
        self.assertIn("reset", r["error"])
        self.assertIn("firewall", r["error"])
        self.assertTrue(r.get("hint"))
        # blocked probes must be N/T (None), never protocol "no" (False)
        for name in ("SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
            self.assertIsNone(r["protocols"][name]["supported"], name)

    def test_proxy_fallback_produces_full_openssl_result(self):
        pxy, hits, close = start_proxy(
            portmap={("blocked.example", self.rst): ("127.0.0.1", self.tls)})
        proxy = sslcheck._parse_proxy_url("http://127.0.0.1:%d" % pxy)
        proxy["source"] = "SSLCHECK_PROXY"
        # the target hostname resolves nowhere here, so pin resolution and
        # proxy discovery (their env parsing is unit-tested above)
        with mock.patch.object(sslcheck, "_proxy_for", return_value=proxy), \
             mock.patch.object(sslcheck, "_pick_addr",
                               return_value="127.0.0.1"), \
             mock.patch.object(sslcheck, "_resolve_any",
                               return_value="127.0.0.1"):
            # make the direct baseline hit the RST listener
            real = sslcheck._s_client

            def routed(host, port, extra, **kw):
                t = kw.get("transport") or {}
                if t.get("via") != "proxy":
                    return real("127.0.0.1", self.rst, extra, **kw)
                return real(host, port, extra, **kw)
            with mock.patch.object(sslcheck, "_s_client", side_effect=routed):
                r = sslcheck.offline_check("blocked.example", self.rst)
        close()
        self.assertTrue(r.get("proxy_used"), r.get("error"))
        self.assertEqual(r.get("engine"), "openssl")
        self.assertGreater(len(hits), 5)                 # real CONNECT tunnels
        self.assertTrue(r["protocols"]["TLSv1.2"]["supported"])
        self.assertTrue(r["protocols"]["TLSv1.3"]["supported"])
        self.assertEqual(r["cert"]["cn"], "localhost")
        self.assertIn("TLS_AES_128_GCM_SHA256", r["ciphers"]["TLSv1.3"])
        self.assertTrue(any("egress proxy" in n for n in r["notes"]))

    def test_authenticating_proxy_python_rescue(self):
        pxy, hits, close = start_proxy(
            portmap={("blocked.example", self.rst): ("127.0.0.1", self.tls)},
            auth="user:secret")
        proxy = sslcheck._parse_proxy_url(
            "http://user:secret@127.0.0.1:%d" % pxy)
        proxy["source"] = "SSLCHECK_PROXY"
        with mock.patch.object(sslcheck, "_proxy_for", return_value=proxy), \
             mock.patch.object(sslcheck, "_pick_addr",
                               return_value="127.0.0.1"), \
             mock.patch.object(sslcheck, "_resolve_any",
                               return_value="127.0.0.1"):
            real = sslcheck._s_client

            def routed(host, port, extra, **kw):
                t = kw.get("transport") or {}
                if t.get("via") != "proxy":
                    return real("127.0.0.1", self.rst, extra, **kw)
                return real(host, port, extra, **kw)     # -proxy: no auth → 407
            real_tun = sslcheck._tunnel_sock

            def tun(host, port, proxy=None, timeout=10):
                if proxy is None:                          # direct = RST wall
                    return real_tun("127.0.0.1", self.rst, None, timeout)
                return real_tun(host, port, proxy, timeout)  # proxy remaps
            with mock.patch.object(sslcheck, "_s_client", side_effect=routed), \
                 mock.patch.object(sslcheck, "_tunnel_sock", side_effect=tun):
                # let the CONNECT proxy do the port re-mapping itself
                r = sslcheck.offline_check("blocked.example", self.rst)
        close()
        self.assertEqual(r.get("engine"), "python-ssl", r.get("error"))
        self.assertTrue(r.get("proxy_used"))
        self.assertGreater(len(hits), 3)                 # authed tunnels
        self.assertEqual((r.get("cert") or {}).get("cn"), "localhost")
        self.assertTrue(r["protocols"]["TLSv1.2"]["supported"])
        self.assertTrue(r["protocols"]["TLSv1.3"]["supported"])
        self.assertTrue(any("Python TLS engine" in n for n in r["notes"]))


class TestDirectStillWorks(unittest.TestCase):
    """Regression: direct targets behave exactly as before."""

    @classmethod
    def setUpClass(cls):
        _clearenv()
        cls.tls, cls._c = start_tls()

    @classmethod
    def tearDownClass(cls):
        cls._c()

    def test_local_tls_grade_T_and_matrix(self):
        r = sslcheck.offline_check("localhost", self.tls)
        self.assertEqual(r["grade"], "T")                 # self-signed
        self.assertEqual(r["transport"], "direct")
        self.assertEqual(r["engine"], "openssl")
        self.assertTrue(r["protocols"]["TLSv1.2"]["supported"])
        self.assertTrue(r["protocols"]["TLSv1.3"]["supported"])
        self.assertEqual(r["cert"]["cn"], "localhost")
        self.assertTrue(r["hostname_match"])
        self.assertFalse(r["trusted"])
        self.assertIn("TLS_AES_128_GCM_SHA256", r["ciphers"]["TLSv1.3"])
        self.assertTrue(r["hsts"]["present"])             # served by the stub

    def test_matrix_cipher_from_handshake_line(self):
        """TLS 1.3 must not flake on the racy 'Cipher    :' session block."""
        for _ in range(4):
            r = sslcheck.offline_check("localhost", self.tls)
            self.assertTrue(r["protocols"]["TLSv1.3"]["supported"],
                            r["protocols"])


class TestPreciseErrors(unittest.TestCase):
    def setUp(self):
        _clearenv()

    def test_classifier_ignores_thread_id_hex(self):
        """OpenSSL's random thread-id prefix can start with '407' — that must
        never be read as an HTTP 407 proxy-auth reply (seen in production)."""
        err = ("4077A4F2C4760000:error:0A00010B:SSL routines:"
               "ssl3_get_record:wrong version number:"
               "../ssl/record/ssl3_record.c:354:")
        kind, _ = sslcheck._classify(1, "", err)
        self.assertEqual(kind, "plaintext")
        # a REAL proxy-auth reply still classifies correctly
        kind, _ = sslcheck._classify(
            1, "", "s_client: HTTP CONNECT failed: "
                   "407 Proxy Authentication Required")
        self.assertEqual(kind, "proxyauth")
        # and a reset is still a reset even with an unlucky hex prefix
        kind, _ = sslcheck._classify(1, "", "4070000:write:errno=104")
        self.assertEqual(kind, "reset")

    def test_dead_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
        s.close()
        r = sslcheck.offline_check("127.0.0.1", dead)
        self.assertEqual(r["grade"], "-")
        self.assertTrue(r.get("error"))
        self.assertIn("port", r.get("hint", ""))

    def test_plaintext_service(self):
        import http.server
        import socketserver

        class Q(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass
        httpd = socketserver.TCPServer(("127.0.0.1", 0), Q)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            r = sslcheck.offline_check("127.0.0.1", port)
            self.assertEqual(r["grade"], "-")
            self.assertIn("plaintext", r["error"])
            self.assertIn("443", r.get("hint", ""))
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
