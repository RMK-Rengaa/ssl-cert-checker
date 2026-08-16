"""
sslcheck — a TLS/SSL checker that works even where the network fights back.

Point it at any hostname, IP, or full URL and it produces an SSL-Labs-style
report card: protocol matrix (SSLv3 -> TLS 1.3), negotiated ciphers, the full
served chain, trust + hostname verification, days to expiry, HSTS, forward
secrecy, ALPN, common weaknesses, and a letter grade (A+ / A / B / C / D /
F / T / -).

Two modes:

* OFFLINE (default) — this machine probes the target itself with the
  openssl binary.  Built for hosts inside restricted networks:

    1. TRANSPORT AUTO-SELECTION.  Every run first tries a direct
       connection; if the direct TLS handshake is blocked (firewall RST,
       timeout, no route) and an egress proxy is configured — via
       SSLCHECK_PROXY or the standard https_proxy / HTTPS_PROXY /
       all_proxy / http_proxy variables, honouring no_proxy — the whole
       run transparently switches to `openssl s_client -proxy` (HTTP
       CONNECT) and is pinned there so all results stay coherent.
       Loopback and no_proxy hosts are never proxied.
    2. PYTHON-SSL RESCUE ENGINE.  If openssl cannot complete a handshake
       on either transport (missing binary, local policy, or a proxy that
       requires Basic authentication — which `s_client -proxy` cannot
       speak), the probe is redone with Python's own ssl module through a
       manual CONNECT tunnel: leaf certificate, protocol matrix, ALPN,
       trust and hostname verdicts still come back instead of a bare
       error.
    3. HONEST DIAGNOSTICS.  A probe that is blocked/reset is reported as
       "not testable" — never as protocol "no".  Errors carry a
       plain-language diagnosis plus a hint naming the next step, and
       every result states which transport and engine produced it.  If
       the certificate name matches but the chain anchors to a private
       root, the report says so — TLS-intercepting middleboxes are
       detected, not mistaken for broken sites.
    4. URLS JUST WORK.  `http://host/path` pasted into a TLS checker
       targets port 443 (the site's TLS endpoint); an explicit port
       (host:8443) is always respected.

* ONLINE — the public online SSL/TLS assessment assessment via api.ssllabs.com,
  summarised into the same result shape (SSL Labs only assesses port
  443).  Base URL overridable with the SSLLABS_API environment variable.

Pure stdlib + the openssl binary.  No third-party packages.

CLI:      python3 sslcheck.py example.com [more targets] [options]
Library:  from sslcheck import offline_check, online_check
"""

__version__ = "1.0.0"


import base64
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import warnings

OPENSSL_TIMEOUT = 25
PROBE_TIMEOUT = 12          # per protocol/cipher probe
BASELINE_TIMEOUT = 15       # the first full handshake per transport

# a bounded, representative candidate list for the per-protocol cipher scan
TLS12_CANDIDATES = [
    "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-SHA256",
    "AES128-GCM-SHA256", "AES256-GCM-SHA384", "AES128-SHA",
    "DHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-DES-CBC3-SHA", "RC4-SHA",
]
TLS13_CANDIDATES = [
    "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
]
WEAK_MARKERS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5")


def _run(cmd, input_bytes=None, timeout=OPENSSL_TIMEOUT):
    try:
        p = subprocess.run(cmd, input=input_bytes, capture_output=True,
                           timeout=timeout)
        return (p.returncode,
                p.stdout.decode("utf-8", "replace"),
                p.stderr.decode("utf-8", "replace"))
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after %ss" % timeout
    except FileNotFoundError:
        return 127, "", "openssl binary not found"


def _is_ip(host):
    """True for IPv4 / IPv6 literals (RFC 6066 forbids IPs in SNI)."""
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, host)
            return True
        except OSError:
            pass
    return False


def _pick_addr(host, port, timeout=8):
    """Resolve host and return the first address that actually accepts a TCP
    connection — pinning every subsequent probe to ONE endpoint (a hostname
    like localhost can map to both ::1 and 127.0.0.1, and mixed picks make
    per-protocol results incoherent)."""
    err = None
    for fam, _t, _p, _c, sa in socket.getaddrinfo(host, port,
                                                  type=socket.SOCK_STREAM):
        try:
            s = socket.socket(fam, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(sa)
            s.close()
            return sa[0]
        except OSError as e:
            err = e
    raise OSError(err or "no address for %s" % host)


def _resolve_any(host):
    """Best-effort DNS for display only (no connect test) — the proxy may be
    able to reach a name this host cannot connect to (or even resolve)."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return infos[0][4][0] if infos else ""
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# egress proxy discovery + transport plumbing
# ---------------------------------------------------------------------------

def _parse_proxy_url(val):
    """'http://user:pass@proxy:3128' / 'proxy:3128' -> dict or None."""
    v = (val or "").strip().strip("'\"")
    if not v:
        return None
    if "://" not in v:
        v = "http://" + v
    try:
        u = urllib.parse.urlparse(v)
        if not u.hostname:
            return None
        auth = None
        if u.username:
            auth = "%s:%s" % (urllib.parse.unquote(u.username),
                              urllib.parse.unquote(u.password or ""))
        return {"host": u.hostname, "port": int(u.port or 3128),
                "auth": auth, "url": v}
    except (ValueError, TypeError):
        return None


def _host_in_no_proxy(host, no_proxy):
    """no_proxy matching: '*', exact host, domain suffix (with or without a
    leading dot), 'host:port' entries compared on the host part.  CIDR
    entries are not interpreted (rarely used; treated as literal hosts)."""
    h = (host or "").lower().rstrip(".")
    for raw in (no_proxy or "").split(","):
        e = raw.strip().lower().rstrip(".")
        if not e:
            continue
        if e == "*":
            return True
        e = e.split(":", 1)[0].split("/", 1)[0]      # drop :port / CIDR tail
        if not e:
            continue
        if h == e:
            return True
        if e.startswith(".") and h.endswith(e):
            return True
        if h.endswith("." + e):
            return True
    return False


def _proxy_for(host):
    """The egress proxy to use as a FALLBACK for this host, or None.
    Order: SSLCHECK_PROXY (tool-specific override), then the standard
    https_proxy / HTTPS_PROXY / all_proxy / ALL_PROXY / http_proxy /
    HTTP_PROXY.  no_proxy / NO_PROXY is honoured; loopback targets and the
    private/internal names covered by no_proxy are
    never proxied."""
    h = (host or "").lower().rstrip(".")
    if h in ("localhost",) or h.endswith(".localhost"):
        return None
    if _is_ip(h):
        try:
            fam = socket.AF_INET6 if ":" in h else socket.AF_INET
            packed = socket.inet_pton(fam, h)
            if fam == socket.AF_INET and packed[0] == 127:
                return None
            if fam == socket.AF_INET6 and packed == b"\0" * 15 + b"\1":
                return None
        except OSError:
            pass
    npx = os.environ.get("no_proxy") or os.environ.get("NO_PROXY") or ""
    if _host_in_no_proxy(h, npx):
        return None
    for var in ("SSLCHECK_PROXY", "https_proxy", "HTTPS_PROXY",
                "all_proxy", "ALL_PROXY", "http_proxy", "HTTP_PROXY"):
        p = _parse_proxy_url(os.environ.get(var, ""))
        if p:
            p["source"] = var
            return p
    return None


def _direct_transport(ip=None):
    return {"via": "direct", "ip": ip, "label": "direct"}


def _proxy_transport(proxy):
    return {"via": "proxy", "proxy": proxy,
            "label": "proxy %s:%d" % (proxy["host"], proxy["port"])}


def _s_client(host, port, extra, servername=None, connect_ip=None,
              timeout=OPENSSL_TIMEOUT, transport=None):
    """Run `openssl s_client` against host:port over the given transport
    (direct, or HTTP CONNECT through an egress proxy).  SNI is sent for
    hostnames only — RFC 6066 forbids IP literals, and some front ends
    reset handshakes that carry one."""
    cmd = ["openssl", "s_client"]
    if transport and transport.get("via") == "proxy":
        pr = transport["proxy"]
        hostpart = "[%s]" % host if ":" in host else host
        cmd += ["-connect", "%s:%d" % (hostpart, port),
                "-proxy", "%s:%d" % (pr["host"], pr["port"])]
    else:
        ip = connect_ip or (transport or {}).get("ip") or host
        hostpart = "[%s]" % ip if ":" in ip else ip
        cmd += ["-connect", "%s:%d" % (hostpart, port)]
    sni = servername or host
    if sni and not _is_ip(sni):
        cmd += ["-servername", sni]
    cmd += extra
    return _run(cmd, input_bytes=b"", timeout=timeout)


# ---- failure classification (so a blocked probe is never called a "no") ---

_FAIL_PATTERNS = [
    # text-specific patterns first; numeric codes only in anchored phrases —
    # a bare "407" collides with openssl's random thread-id hex prefix
    ("plaintext",  ("wrong version number", "packet length too long",
                    "http request", "unknown protocol")),
    ("proxyauth",  ("proxy authentication required", "http/1.0 407",
                    "http/1.1 407", "connect failed: 407")),
    ("proxy",      ("http connect failed", "proxy connect",
                    "error connecting to proxy", "connect to proxy")),
    ("reset",      ("errno=104", "connection reset", "econnreset")),
    ("timeout",    ("timeout", "errno=110", "timed out")),
    ("refused",    ("errno=111", "connection refused")),
    ("unreachable", ("errno=113", "errno=101", "no route to host",
                     "network is unreachable")),
    ("dns",        ("getaddrinfo", "name or service not known",
                    "nodename nor servname", "temporary failure in name")),
    ("local",      ("no protocols available", "null ssl method",
                    "unknown option", "binary not found")),
    ("tls-alert",  ("alert protocol version", "alert handshake failure",
                    "handshake failure", "sslv3 alert", "internal error",
                    "unsupported protocol", "no cipher match",
                    "no ciphers available", "alert close notify",
                    "dh key too small", "ee key too small",
                    "certificate verify failed")),
]


def _classify(rc, out, err):
    """(kind, one-line detail) for a failed/successful s_client run."""
    if rc == 0 and "BEGIN CERTIFICATE" in out:
        return "ok", ""
    blob = (out + "\n" + err).lower()
    if rc == 124:
        return "timeout", (err.strip() or "timed out")
    for kind, needles in _FAIL_PATTERNS:
        for n in needles:
            if n in blob:
                detail = next((ln.strip() for ln in (err + out).splitlines()
                               if n in ln.lower()), n)
                return kind, detail[:160]
    if rc == 0:
        return "nocert", "handshake completed but no certificate was served"
    tail = (err.strip() or out.strip()).splitlines()
    return "other", (tail[-1][:160] if tail else "handshake failed")


_KIND_HUMAN = {
    "reset": "TCP connect succeeded but the TLS handshake was reset "
             "(typical of an egress firewall or an intercepting proxy)",
    "timeout": "connection timed out (filtered port or no route)",
    "refused": "connection refused (nothing listening on the port)",
    "unreachable": "network unreachable from this host",
    "dns": "hostname did not resolve from this host",
    "plaintext": "the service answered in plaintext — no TLS on this port",
    "proxyauth": "the egress proxy requires authentication",
    "proxy": "the egress proxy refused the CONNECT to the target",
    "local": "the local openssl cannot run this probe",
    "nocert": "handshake completed but no certificate was served",
    "other": "TLS handshake failed",
}


def _human_fail(kind, detail):
    base = _KIND_HUMAN.get(kind, "TLS handshake failed")
    return "%s [%s]" % (base, detail) if detail else base


def _pick_transport(host, port, direct_ip, log=lambda m: None):
    """Try a full `-showcerts` handshake directly; if that is blocked at the
    network layer and an egress proxy is configured, retry through it.  The
    winning transport is pinned for the whole run.  Returns
    (transport | None, baseline_out, baseline_err, diagnostics)."""
    diag = {"proxy_available": None, "direct": None, "proxy": None}
    t = _direct_transport(direct_ip)
    log("baseline handshake (direct)")
    rc, out, err = _s_client(host, port, ["-showcerts"], transport=t,
                             timeout=BASELINE_TIMEOUT)
    kind, detail = _classify(rc, out, err)
    diag["direct"] = {"kind": kind, "detail": detail}
    if kind == "ok":
        return t, out, err, diag
    if kind in ("plaintext", "nocert", "tls-alert"):
        # the target answered — a proxy would not change the outcome
        return None, out, err, diag

    proxy = _proxy_for(host)
    diag["proxy_available"] = bool(proxy)
    if proxy and kind in ("reset", "timeout", "refused", "unreachable",
                          "dns", "local", "other"):
        pt = _proxy_transport(proxy)
        log("direct path blocked (%s) — retrying via %s [%s]"
            % (kind, pt["label"], proxy.get("source", "env")))
        rc, pout, perr = _s_client(host, port, ["-showcerts"], transport=pt,
                                   timeout=BASELINE_TIMEOUT + 5)
        pkind, pdetail = _classify(rc, pout, perr)
        diag["proxy"] = {"kind": pkind, "detail": pdetail,
                         "proxy": "%s:%d" % (proxy["host"], proxy["port"])}
        if pkind == "ok":
            return pt, pout, perr, diag
    return None, out, err, diag


def _pem_blocks(text):
    out, cur, on = [], [], False
    for ln in text.splitlines():
        if "-----BEGIN CERTIFICATE-----" in ln:
            on, cur = True, [ln]
        elif "-----END CERTIFICATE-----" in ln and on:
            cur.append(ln)
            out.append("\n".join(cur) + "\n")
            on = False
        elif on:
            cur.append(ln)
    return out


def _x509_info(pem):
    """subject / issuer / SANs / serial / dates / key / sig via openssl."""
    info = {}
    rc, out, _ = _run(["openssl", "x509", "-noout", "-subject", "-issuer",
                       "-serial", "-startdate", "-enddate", "-nameopt",
                       "RFC2253"], input_bytes=pem.encode())
    if rc == 0:
        for ln in out.splitlines():
            k, _, v = ln.partition("=")
            info[k.strip().lower()] = v.strip()
    subj = info.get("subject", "")
    m = re.search(r"CN=([^,]+)", subj)
    info["cn"] = (m.group(1) if m else subj).strip()
    im = re.search(r"CN=([^,]+)", info.get("issuer", ""))
    info["issuer_cn"] = (im.group(1) if im else info.get("issuer", "")).strip()
    rc, out, _ = _run(["openssl", "x509", "-noout", "-text"],
                      input_bytes=pem.encode())
    if rc == 0:
        sm = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*(.+)", out)
        info["sans"] = ([s.strip()[4:] for s in sm.group(1).split(",")
                         if s.strip().startswith("DNS:")] if sm else [])
        if sm:
            info["ip_sans"] = [s.strip()[len("IP Address:"):]
                               for s in sm.group(1).split(",")
                               if s.strip().startswith("IP Address:")]
        km = re.search(r"Public-Key:\s*\((\d+) bit\)", out)
        info["key_bits"] = int(km.group(1)) if km else 0
        info["key_type"] = ("EC" if "id-ecPublicKey" in out else
                            "RSA" if "rsaEncryption" in out else "?")
        gm = re.search(r"Signature Algorithm:\s*(\S+)", out)
        info["sig_alg"] = gm.group(1) if gm else ""
    # days to expiry
    info["days_left"] = None
    rc, out, _ = _run(["openssl", "x509", "-noout", "-enddate"],
                      input_bytes=pem.encode())
    if rc == 0 and "=" in out:
        try:
            from datetime import datetime, timezone
            end = out.strip().split("=", 1)[1]
            dt = datetime.strptime(end, "%b %d %H:%M:%S %Y %Z")
            info["days_left"] = int(
                (dt.replace(tzinfo=timezone.utc)
                 - datetime.now(timezone.utc)).total_seconds() // 86400)
        except Exception:
            pass
    return info


def _hostname_matches(host, cert_info):
    h = (host or "").lower().rstrip(".")
    if _is_ip(h):
        return h in [(x or "").strip() for x in cert_info.get("ip_sans") or []]
    names = [cert_info.get("cn", "")] + (cert_info.get("sans") or [])
    for n in names:
        n = (n or "").lower().rstrip(".")
        if not n:
            continue
        if n == h:
            return True
        if n.startswith("*.") and h.endswith(n[1:]) and h.count(".") == n.count("."):
            return True
    return False


def _normalise_target(raw):
    """Strip URL scheme + path so the user can paste a full browser URL
    (hardened — never lets a path/scheme fragment reach int();
     an http:// URL WITHOUT an explicit port targets 443 — this is
     a TLS checker, so 'check http://site/…' means 'check the site's TLS
     endpoint', exactly like the Online check and every public SSL tester.
     An explicit port is always respected):
    https://host/path        ->  host, 443
    http://host/path         ->  host, 443   (TLS-checker intent)
    http://host:8080/path    ->  host, 8080
    host/path?query          ->  host, 443
    host:port                ->  host, port
    [::1]:8443 / bare IPv6   ->  address, port/443
    user@host                ->  host, 443
    host                     ->  host, 443"""
    import urllib.parse as _up
    s = str(raw or "").strip().strip("'\"")
    if not s:
        raise ValueError("empty target")
    if "://" in s:
        parsed = _up.urlparse(s)
        host = parsed.hostname
        if not host:
            raise ValueError("no hostname found in %r" % raw)
        try:
            port = parsed.port
        except ValueError:                       # e.g. https://host:junk/
            port = None
        return str(host), int(port or 443)
    # scheme-less forms: strip path / query / fragment / userinfo first
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if s.startswith("["):                        # [IPv6] or [IPv6]:port
        h, _, rest = s[1:].partition("]")
        p = rest.lstrip(":").strip()
        return h, (int(p) if p.isdigit() else 443)
    if s.count(":") > 1:                         # bare IPv6, no port
        return s, 443
    if ":" in s:
        h, _, pstr = s.rpartition(":")
        pstr = pstr.strip()
        if pstr.isdigit():
            return h.strip(), int(pstr)
        return s, 443
    return s, 443


# ---------------------------------------------------------------------------
# pure-Python secondary engine (manual CONNECT tunnel + ssl module).
# Used when the openssl binary cannot complete a handshake on any transport:
# missing binary, security-level policy, or an authenticating proxy (which
# `s_client -proxy` cannot speak Basic auth to).
# ---------------------------------------------------------------------------

def _tunnel_sock(host, port, proxy=None, timeout=10):
    """A connected TCP socket to host:port — through an HTTP CONNECT proxy
    (with optional Basic auth) when one is given."""
    if not proxy:
        return socket.create_connection((host, port), timeout=timeout)
    s = socket.create_connection((proxy["host"], proxy["port"]),
                                 timeout=timeout)
    try:
        hostpart = "[%s]" % host if ":" in host else host
        req = ("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
               % (hostpart, port, hostpart, port))
        if proxy.get("auth"):
            req += ("Proxy-Authorization: Basic %s\r\n"
                    % base64.b64encode(proxy["auth"].encode()).decode())
        req += "\r\n"
        s.sendall(req.encode())
        s.settimeout(timeout)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 8192:
            chunk = s.recv(1024)
            if not chunk:
                break
            buf += chunk
        line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        m = re.match(r"HTTP/\d\.\d\s+(\d{3})", line)
        code = int(m.group(1)) if m else 0
        if code != 200:
            s.close()
            raise OSError("proxy CONNECT failed: %s" % (line.strip() or code))
        return s
    except Exception:
        try:
            s.close()
        except OSError:
            pass
        raise


_PY_PROTOS = [
    ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
    ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
]


def _py_handshake(host, port, proxy, ver=None, verify=False,
                  check_host=True, alpn=None, timeout=10):
    """One handshake with Python's ssl.  Returns (ssl-facts dict) or raises.
    The socket is closed before returning."""
    ctx = (ssl.create_default_context() if verify
           else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif not check_host or _is_ip(host):
        ctx.check_hostname = False
    if ver is not None:
        with warnings.catch_warnings():
            # probing TLS 1.0/1.1 support is the point — the deprecation
            # warning would just spam the log on every legacy probe
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ver
            ctx.maximum_version = ver
        if ver in (getattr(ssl.TLSVersion, "TLSv1", None),
                   getattr(ssl.TLSVersion, "TLSv1_1", None)):
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except NotImplementedError:
            pass
    raw = _tunnel_sock(host, port, proxy, timeout=timeout)
    try:
        sni = None if _is_ip(host) else host
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            der = tls.getpeercert(binary_form=True)
            return {"version": tls.version(),
                    "cipher": (tls.cipher() or ("",))[0],
                    "alpn": tls.selected_alpn_protocol(),
                    "der": der}
    finally:
        try:
            raw.close()
        except OSError:
            pass


def _py_rescue(host, port, proxy, log=lambda m: None):
    """Full best-effort probe with the Python engine: try direct first, then
    the proxy.  Returns a partial result dict or None if nothing connected."""
    for pr, label in ((None, "direct"), (proxy, proxy and
                      "proxy %s:%d" % (proxy["host"], proxy["port"]))):
        if pr is None and label is None:
            continue
        if pr is proxy and not proxy:
            continue
        try:
            log("python-ssl engine (%s)" % label)
            base = _py_handshake(host, port, pr,
                                 alpn=["h2", "http/1.1"], timeout=10)
        except Exception as e:
            log("python-ssl %s failed: %s" % (label, str(e)[:120]))
            continue

        out = {"engine": "python-ssl",
               "transport": label if pr else "direct",
               "proxy_used": bool(pr),
               "protocols": {"SSLv2": {"supported": False, "cipher": ""},
                             "SSLv3": {"supported": None,
                                       "note": "not testable with this engine"}},
               "alpn": [base["alpn"]] if base.get("alpn") else []}
        pem = ssl.DER_cert_to_PEM_cert(base["der"]) if base.get("der") else ""
        if pem:
            info = _x509_info(pem)
            out["chain"] = [info]
            out["cert"] = info
            out["chain_length"] = 1
            out["hostname_match"] = _hostname_matches(host, info)
        # per-protocol matrix
        for name, ver in _PY_PROTOS:
            if ver is None:
                out["protocols"][name] = {"supported": None,
                                          "note": "not testable from this host"}
                continue
            try:
                r = _py_handshake(host, port, pr, ver=ver, timeout=8)
                out["protocols"][name] = {"supported": True,
                                          "cipher": r.get("cipher", "")}
            except ssl.SSLError as e:
                msg = str(e).lower()
                if "no protocols available" in msg or "unsupported" in msg:
                    out["protocols"][name] = {
                        "supported": None,
                        "note": "not testable from this host"}
                else:
                    out["protocols"][name] = {"supported": False, "cipher": ""}
            except Exception:
                out["protocols"][name] = {"supported": None,
                                          "note": "probe blocked"}
        # trust + hostname via a verifying handshake
        try:
            _py_handshake(host, port, pr, verify=True, timeout=10)
            out["trusted"] = True
            if not _is_ip(host):
                out["hostname_match"] = True
        except ssl.SSLCertVerificationError as e:
            msg = str(e)
            if "hostname" in msg.lower():
                out["hostname_match"] = False
                try:                       # name failed — is the chain ok?
                    _py_handshake(host, port, pr, verify=True,
                                  check_host=False, timeout=10)
                    out["trusted"] = True
                except Exception:
                    out["trusted"] = False
                    out["trust_error"] = msg[:200]
            else:
                out["trusted"] = False
                out["trust_error"] = msg[:200]
        except Exception:
            pass                            # leave trust undetermined
        return out
    return None


# ---------------------------------------------------------------------------
# rich probes so the offline report carries the same sections the
# online SSL/TLS assessment report does (certificate detail, cipher strengths, named
# groups, protocol-level vulnerabilities, HTTP + miscellaneous).
# ---------------------------------------------------------------------------

# approximate symmetric strength (bits) keyed by the cipher-name stem
_CIPHER_BITS = [
    ("AES_256", 256), ("AES256", 256), ("AES_128", 128), ("AES128", 128),
    ("CHACHA20", 256), ("3DES", 112), ("DES_CBC3", 112), ("DES", 56),
    ("RC4_128", 128), ("RC4", 128), ("SEED", 128), ("CAMELLIA_256", 256),
    ("CAMELLIA256", 256), ("CAMELLIA_128", 128), ("CAMELLIA128", 128),
    ("NULL", 0),
]


def _cipher_bits(name):
    up = name.upper().replace("-", "_")
    for stem, bits in _CIPHER_BITS:
        if stem in up:
            return bits
    return None


def _is_fs(name):
    up = name.upper()
    return up.startswith(("ECDHE", "DHE", "TLS_AES", "TLS_CHACHA", "TLS_")) \
        or "ECDHE" in up or "DHE_" in up


def _full_handshake(host, port, transport):
    """One rich s_client connection; parse the transport-level facts online SSL/TLS assessment
    surfaces (secure renegotiation, compression, session ticket, ALPN, OCSP
    stapling, negotiated named group / temp key)."""
    d = {"secure_renegotiation": None, "compression": None,
         "session_ticket": None, "alpn": [], "ocsp_stapling": None,
         "named_group": None, "server_temp_key": None, "npn": None}
    rc, out, err = _s_client(host, port,
                             ["-tlsextdebug", "-status", "-alpn",
                              "h2,http/1.1"], transport=transport)
    blob = out + err
    if "Secure Renegotiation IS supported" in blob:
        d["secure_renegotiation"] = True
    elif "Secure Renegotiation IS NOT supported" in blob:
        d["secure_renegotiation"] = False
    m = re.search(r"Compression:\s*(\S+)", blob)
    if m:
        d["compression"] = (m.group(1).upper() != "NONE")
    if re.search(r"TLS session ticket lifetime hint:\s*[1-9]", blob) \
            or re.search(r"TLS session ticket:\s*\n", blob):
        d["session_ticket"] = True
    elif "TLS session ticket lifetime hint: 0" in blob \
            or ("New," in blob and "session ticket" not in blob.lower()):
        d["session_ticket"] = False
    am = re.search(r"ALPN protocol:\s*(\S+)", blob)
    if am:
        d["alpn"] = [am.group(1)]
    elif "No ALPN negotiated" in blob:
        d["alpn"] = []
    # NPN is deprecated; probe it separately with a VALID list (an empty
    # argument makes openssl abort the whole handshake), tolerate old builds.
    try:
        rcn, on, en = _s_client(host, port,
                                ["-nextprotoneg", "http/1.1"],
                                transport=transport, timeout=PROBE_TIMEOUT)
        nb = on + en
        if "Error parsing" in nb or "unknown option" in nb:
            d["npn"] = None
        else:
            d["npn"] = bool(re.search(r"Next protocol:\s*\(\d+\)\s*\S+", nb))
    except Exception:
        d["npn"] = None
    if "OCSP Response Status: successful" in blob:
        d["ocsp_stapling"] = True
    elif "OCSP response: no response sent" in blob \
            or "OCSP response:  no response sent" in blob:
        d["ocsp_stapling"] = False
    tk = re.search(r"Server Temp Key:\s*(.+)", blob)
    if tk:
        d["server_temp_key"] = tk.group(1).strip()
        gm = re.search(r"(X25519|X448|P-256|P-384|P-521|secp\d+r1|ffdhe\d+)",
                       tk.group(1))
        if gm:
            d["named_group"] = gm.group(1)
    return d


def _reconnect_resumes(host, port, transport):
    """Session resumption (caching): -reconnect does 5 handshakes; a resumed
    one prints 'Reused'."""
    rc, out, err = _s_client(host, port, ["-reconnect"], transport=transport,
                             timeout=OPENSSL_TIMEOUT)
    blob = out + err
    if "Reused, TLS" in blob or "Reused, SSL" in blob:
        return True
    # count session-id reuse markers as a fallback
    if blob.count("Reused") >= 1:
        return True
    if "New, " in blob and "Reused" not in blob:
        return False
    return None


def _supports_fallback_scsv(host, port, transport, protocols):
    """Real downgrade-protection probe: connect asking for a protocol BELOW
    the server's best while advertising TLS_FALLBACK_SCSV.  A protected
    server answers with an 'inappropriate fallback' alert (the handshake
    fails on purpose).  Returns True when that happens; None when the
    server offers no lower protocol to fall back to (SCSV untestable)."""
    order = ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0"]
    flags = {"TLSv1.2": "-tls1_2", "TLSv1.1": "-tls1_1", "TLSv1.0": "-tls1"}
    supported = [p for p in order if protocols.get(p, {}).get("supported")]
    if len(supported) < 2:
        return None
    lower = supported[1]                      # one notch below the best
    flag = flags.get(lower)
    if not flag:
        return None
    rc, out, err = _s_client(host, port, [flag, "-fallback_scsv"],
                             transport=transport, timeout=PROBE_TIMEOUT)
    blob = (out + err).lower()
    if "inappropriate fallback" in blob or "tlsv1 alert inappropriate" in blob:
        return True
    if rc == 0 and "BEGIN CERTIFICATE" in out:
        return False
    return None


def _named_groups(host, port, transport):
    """Which curves/groups the server accepts (bounded probe)."""
    groups = ["X25519", "P-256", "P-384", "P-521", "X448"]
    ok = []
    for g in groups:
        rc, out, err = _s_client(host, port, ["-groups", g],
                                 transport=transport, timeout=PROBE_TIMEOUT)
        if rc == 0 and "BEGIN CERTIFICATE" in out:
            ok.append(g)
    return ok


def _leaf_extensions(pem):
    """Certificate-level facts online SSL/TLS assessment lists: fingerprint, serial, not-before,
    EV, Certificate Transparency (SCT), OCSP-must-staple, CRL + OCSP URIs."""
    d = {"fingerprint_sha256": "", "serial": "", "not_before": "",
         "ev": False, "sct": False, "must_staple": False,
         "crl": [], "ocsp": [], "ca_issuers": []}
    rc, out, _ = _run(["openssl", "x509", "-noout", "-fingerprint", "-sha256",
                       "-serial", "-startdate"], input_bytes=pem.encode())
    if rc == 0:
        for ln in out.splitlines():
            low = ln.lower()
            if "fingerprint=" in low and not d["fingerprint_sha256"]:
                d["fingerprint_sha256"] = ln.split("=", 1)[1].strip()
            elif low.startswith("serial="):
                d["serial"] = ln.split("=", 1)[1].strip()
            elif low.startswith("notbefore="):
                d["not_before"] = ln.split("=", 1)[1].strip()
    rc, out, _ = _run(["openssl", "x509", "-noout", "-text"],
                      input_bytes=pem.encode())
    if rc == 0:
        if "CT Precertificate SCTs" in out or "1.3.6.1.4.1.11129.2.4.2" in out:
            d["sct"] = True
        # EV via well-known CA/Browser Forum policy OIDs (2.23.140.1.1) or any
        # non-DV/OV policy present in the cert policies block
        if "2.23.140.1.1" in out:
            d["ev"] = True
        if "TLS Web Server Authentication" in out and "status_request" in out \
                or "1.3.6.1.5.5.7.1.24" in out:
            d["must_staple"] = True
        for m in re.finditer(r"URI:(http[^\s]+)", out):
            u = m.group(1)
            if "crl" in u.lower() or u.lower().endswith(".crl"):
                d["crl"].append(u)
        # OCSP + CA Issuers live under Authority Information Access
        aia = re.search(r"Authority Information Access:(.*?)(?:\n\n|\Z)",
                        out, re.S)
        if aia:
            for m in re.finditer(r"OCSP - URI:(\S+)", aia.group(1)):
                d["ocsp"].append(m.group(1))
            for m in re.finditer(r"CA Issuers - URI:(\S+)", aia.group(1)):
                d["ca_issuers"].append(m.group(1))
    return d


def _caa(host):
    """CAA records for the registrable domain (best effort, needs dig)."""
    if _is_ip(host):
        return []
    labels = host.split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        rc, out, _ = _run(["dig", "+short", "CAA", name], timeout=6)
        if rc == 0 and out.strip():
            return [ln.strip() for ln in out.splitlines() if ln.strip()]
        if rc == 127:
            return None            # dig not installed
    return []


def _reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _blocked_protocol_matrix(reason):
    m = {"SSLv2": {"supported": False, "cipher": ""}}
    for name in ("SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
        m[name] = {"supported": None, "note": "not testable — %s" % reason}
    return m


def _fail_hint(kind, diag, host):
    """An actionable next step for the operator, shown under the error."""
    proxy_avail = diag.get("proxy_available")
    if kind == "proxyauth":
        return ("The egress proxy requires authentication — set "
                "SSLCHECK_PROXY=http://user:pass@proxy:port in this host's "
                "environment (the Python engine will authenticate), or use "
                "the Online check.")
    if kind in ("reset", "timeout", "unreachable", "dns"):
        if proxy_avail is False:
            return ("This host cannot reach %s directly and no egress "
                    "proxy is configured.  Set https_proxy (or "
                    "SSLCHECK_PROXY) in the environment, or use the "
                    "Online check — it assesses the target from the internet."
                    % host)
        if proxy_avail:
            p = (diag.get("proxy") or {})
            return ("Direct access is blocked and the configured proxy "
                    "could not reach the target either (%s).  Verify the "
                    "proxy allows CONNECT to %s:443, or use the Online check."
                    % (p.get("detail") or p.get("kind") or "no response",
                       host))
    if kind == "plaintext":
        return ("The service on this port speaks plain HTTP, not TLS — "
                "re-run against the TLS port (usually 443).")
    if kind == "refused":
        return "Nothing is listening on this port — check the port number."
    if kind == "local":
        return ("The local openssl build cannot run this probe — the "
                "Python engine was tried as a fallback; if results are "
                "still incomplete, use the Online check.")
    return "If the target is publicly reachable, the Online check will grade it."


def offline_check(host, port=443, log=lambda m: None):
    """Probe the target the way ssllabs.com does, locally.  Returns a dict
    with the same shape the online summariser produces + extra detail.

    Features: transport auto-selection (direct → egress proxy), a Python-ssl
    rescue engine, and honest N/T reporting for blocked probes."""
    _t0 = time.time()
    host = str(host or "").strip().rstrip(".").lower()
    res = {"mode": "offline", "target": "%s:%d" % (host, port),
           "host": host, "port": port,
           "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
           "protocols": {}, "ciphers": {}, "cipher_detail": {}, "chain": [],
           "weaknesses": [], "notes": [], "vuln": {}, "cert_ext": {},
           "engine": "openssl", "transport": "direct", "proxy_used": False}

    proxy = _proxy_for(host)

    # ---- resolve + direct TCP viability (display + endpoint pinning) -----
    direct_ip, tcp_err = None, None
    try:
        direct_ip = _pick_addr(host, port)
    except OSError as e:
        tcp_err = str(e)
    res["ip"] = direct_ip or _resolve_any(host) or ""
    if res["ip"]:
        res["server_hostname"] = _reverse_dns(res["ip"])
    if direct_ip is None and not proxy:
        # nothing listens / no route, and there is no proxy to fall back to
        res["error"] = "DNS/socket: %s" % tcp_err
        res["hint"] = _fail_hint("timeout" if "timed out" in (tcp_err or "")
                                 else "refused", {"proxy_available": False},
                                 host)
        res["protocols"] = _blocked_protocol_matrix("target unreachable")
        res["grade"] = "-"
        return res

    # ---- pick the transport with one real handshake -----------------------
    transport, base_out, base_err, diag = _pick_transport(
        host, port, direct_ip, log=log)
    res["diagnostics"] = diag

    if transport is None:
        kind = (diag.get("direct") or {}).get("kind", "other")
        detail = (diag.get("direct") or {}).get("detail", "")
        if (diag.get("proxy") or {}).get("kind") == "proxyauth":
            kind, detail = "proxyauth", (diag["proxy"].get("detail") or "")
        # ---- Python-ssl rescue: still try to bring a result home ---------
        rescue = _py_rescue(host, port, proxy, log=log)
        if rescue and rescue.get("cert"):
            res.update(rescue)
            res["notes"].append(
                "the local openssl could not complete the handshake (%s) "
                "— results below come from the built-in Python TLS engine; "
                "cipher scan, served-chain and vulnerability probes are not "
                "available on this path" % _human_fail(kind, detail))
            if res.get("trusted") is None:
                res["notes"].append("chain trust could not be verified from "
                                    "this host")
        else:
            res["error"] = "no certificate returned: %s" % _human_fail(
                kind, detail)
            res["hint"] = _fail_hint(kind, diag, host)
            res["protocols"] = _blocked_protocol_matrix(
                _KIND_HUMAN.get(kind, "probe failed"))
            res["grade"] = "-"
            res["duration_s"] = round(time.time() - _t0, 1)
            return res
    else:
        res["transport"] = transport["label"]
        res["proxy_used"] = transport["via"] == "proxy"
        if res["proxy_used"]:
            res["notes"].append(
                "direct access from this host is blocked — probed through "
                "the egress proxy (%s); results reflect what that path "
                "serves" % transport["label"])

        # ---- protocol matrix (negotiated = server-preferred cipher) ------
        # SSL 2.0 can't be spoken by a modern openssl at all → report as no.
        res["protocols"]["SSLv2"] = {"supported": False, "cipher": ""}
        proto_flags = [("SSLv3", "-ssl3"), ("TLSv1.0", "-tls1"),
                       ("TLSv1.1", "-tls1_1"), ("TLSv1.2", "-tls1_2"),
                       ("TLSv1.3", "-tls1_3")]
        for name, flag in proto_flags:
            log("probe %s" % name)
            rc, out, err = _s_client(host, port, [flag], transport=transport,
                                     timeout=PROBE_TIMEOUT)
            kind, detail = _classify(rc, out, err)
            if kind not in ("ok", "local"):
                # one retry for EVERY failure: sequential/loaded servers can
                # answer a racing handshake with a spurious alert, and a
                # genuinely unsupported protocol re-alerts instantly anyway
                time.sleep(0.25)
                rc, out, err = _s_client(host, port, [flag],
                                         transport=transport,
                                         timeout=PROBE_TIMEOUT)
                kind, detail = _classify(rc, out, err)
            if kind == "local":
                res["protocols"][name] = {"supported": None,
                                          "note": "not testable from this host"}
                continue
            if kind in ("reset", "timeout", "proxy", "unreachable", "dns"):
                # the network interfered — that is NOT a protocol "no"
                res["protocols"][name] = {
                    "supported": None,
                    "note": "not testable — %s" % _KIND_HUMAN.get(kind, kind)}
                continue
            # 'New, TLSv1.3, Cipher is X' prints at handshake completion and
            # is deterministic; the 'Cipher    :' session block races the
            # TLS 1.3 NewSessionTicket and is sometimes missing entirely
            cm = (re.search(r"New, (?:TLSv[\d.]+|SSLv\d), Cipher is (\S+)", out)
                  or re.search(r"Cipher\s+:\s+(\S+)", out))
            cipher = (cm.group(1) if cm and cm.group(1) not in
                      ("0000", "(NONE)") else "")
            ok = kind == "ok"
            res["protocols"][name] = {"supported": bool(ok and cipher),
                                      "cipher": cipher if ok else ""}
        sup = {k: v for k, v in res["protocols"].items() if v.get("supported")}

        # ---- bounded cipher scan on the modern protocols ------------------
        if res["protocols"].get("TLSv1.2", {}).get("supported"):
            good = []
            for c in TLS12_CANDIDATES:
                rc, out, _ = _s_client(host, port, ["-tls1_2", "-cipher", c],
                                       transport=transport,
                                       timeout=PROBE_TIMEOUT)
                if rc == 0 and "Cipher    :" in out and c in out:
                    good.append(c)
            res["ciphers"]["TLSv1.2"] = good
            res["cipher_detail"]["TLSv1.2"] = [
                {"name": c, "bits": _cipher_bits(c), "fs": _is_fs(c)}
                for c in good]
        if res["protocols"].get("TLSv1.3", {}).get("supported"):
            good = []
            for c in TLS13_CANDIDATES:
                rc, out, _ = _s_client(host, port,
                                       ["-tls1_3", "-ciphersuites", c],
                                       transport=transport,
                                       timeout=PROBE_TIMEOUT)
                if rc == 0 and c in out:
                    good.append(c)
            res["ciphers"]["TLSv1.3"] = good
            res["cipher_detail"]["TLSv1.3"] = [
                {"name": c, "bits": _cipher_bits(c), "fs": True} for c in good]

        # ---- supported named groups / curves ------------------------------
        if res["protocols"].get("TLSv1.2", {}).get("supported") \
                or res["protocols"].get("TLSv1.3", {}).get("supported"):
            try:
                log("probe named groups")
                res["named_groups"] = _named_groups(host, port, transport)
            except Exception:
                res["named_groups"] = []

        # ---- served chain + trust (from the baseline handshake) -----------
        pems = _pem_blocks(base_out)
        if not pems:
            rc, out, err = _s_client(host, port, ["-showcerts"],
                                     transport=transport)
            pems = _pem_blocks(out)
            base_err = err
        if not pems:
            kind, detail = _classify(1, "", base_err)
            res["error"] = "no certificate returned: %s" % _human_fail(
                kind, detail or base_err.strip()[:160])
            res["hint"] = _fail_hint(kind, diag, host)
            res["grade"] = "-"
            res["duration_s"] = round(time.time() - _t0, 1)
            return res
        res["chain"] = [_x509_info(p) for p in pems]
        res["cert"] = res["chain"][0]
        res["chain_length"] = len(pems)
        res["certs_provided_bytes"] = sum(len(p.encode()) for p in pems)
        res["chain_issues"] = []
        root_included = any(c.get("subject") and c.get("subject") == c.get("issuer")
                            for c in res["chain"][1:])
        if root_included:
            res["notes"].append("chain contains the (redundant) root anchor")
            res["chain_issues"].append("contains anchor (root certificate "
                                       "served — harmless but redundant)")

        # ---- certificate-level extensions (fingerprint, EV, SCT, CRL/OCSP)
        try:
            res["cert_ext"] = _leaf_extensions(pems[0])
        except Exception:
            res["cert_ext"] = {}
        try:
            res["cert_ext"]["caa"] = _caa(host)
        except Exception:
            res["cert_ext"]["caa"] = None

        # trust: verify leaf against served intermediates + system store
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            leaf = os.path.join(td, "leaf.pem")
            rest = os.path.join(td, "rest.pem")
            with open(leaf, "w") as fh:
                fh.write(pems[0])
            with open(rest, "w") as fh:
                fh.write("".join(pems[1:]))
            cmd = ["openssl", "verify"]
            if len(pems) > 1:
                cmd += ["-untrusted", rest]
            rc, vout, verr = _run(cmd + [leaf])
        res["trusted"] = rc == 0 and ": OK" in vout
        if not res["trusted"]:
            res["trust_error"] = (vout + verr).strip().splitlines()[-1][:200] \
                if (vout + verr).strip() else "verify failed"

        res["hostname_match"] = _hostname_matches(host, res["cert"])

        # a matching name anchored to a private root between us and the
        # target is the classic signature of TLS interception on the path
        if res["hostname_match"] and not res["trusted"] and not _is_ip(host):
            res["notes"].append(
                "the certificate name matches but the chain anchors to a "
                "root this host does not trust — if this network intercepts "
                "TLS, the offline result shows the interception certificate; "
                "the Online check shows the public view")

    # ---- HSTS + HTTP reachability (both engines) --------------------------
    res["hsts"] = res.get("hsts") or {"present": False}

    def _absorb_headers(hdrs):
        if not hdrs:
            return
        h = hdrs.get("Strict-Transport-Security")
        if h:
            ma = re.search(r"max-age=(\d+)", h)
            res["hsts"] = {"present": True, "header": h,
                           "max_age": int(ma.group(1)) if ma else 0,
                           "long": bool(ma and int(ma.group(1)) >= 15552000),
                           "preload": "preload" in h.lower(),
                           "include_subdomains": "includesubdomains" in h.lower()}
        res["http_server"] = hdrs.get("Server", "") or res.get("http_server", "")
        loc = hdrs.get("Location")
        if loc:
            res["http_redirect"] = loc
        for hk, rk in (("Public-Key-Pins", "hpkp"),
                       ("Public-Key-Pins-Report-Only", "hpkp_report_only")):
            if hdrs.get(hk):
                res.setdefault("headers", {})[rk] = hdrs.get(hk)

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if res.get("proxy_used") and proxy:
            url = "https://%s:%d/" % (("[%s]" % host if ":" in host else host),
                                      port)
            handlers = [urllib.request.HTTPSHandler(context=ctx),
                        urllib.request.ProxyHandler(
                            {"https": proxy["url"], "http": proxy["url"]})]
            hdrs = {"User-Agent": "sslcheck/1.0 (+https://github.com/)"}
        else:
            ip = res.get("ip") or host
            hostpart = "[%s]" % ip if ":" in ip else ip
            url = "https://%s:%d/" % (hostpart, port)
            handlers = [urllib.request.HTTPSHandler(context=ctx),
                        urllib.request.ProxyHandler({})]     # force direct
            hdrs = {"User-Agent": "sslcheck/1.0 (+https://github.com/)", "Host": host}
        req = urllib.request.Request(url, headers=hdrs, method="GET")
        opener = urllib.request.build_opener(*handlers)
        r = opener.open(req, timeout=15)
        res["http_status"] = r.status
        _absorb_headers(r.headers)
    except Exception as e:
        res["http_status"] = getattr(e, "code", None) or 0
        _absorb_headers(getattr(e, "headers", None))

    if res.get("engine") == "python-ssl":
        # openssl-only probes are unavailable on the rescue path
        res["vuln"] = {"alpn": res.get("alpn") or []}
        all_ciphers = [v.get("cipher", "") for v in res["protocols"].values()
                       if isinstance(v, dict)]
        res["forward_secrecy"] = any(c.startswith(("ECDHE", "DHE", "TLS_"))
                                     for c in all_ciphers if c)
    else:
        # ---- transport-level facts + protocol vulnerabilities -------------
        log("probe transport features")
        try:
            hs = _full_handshake(host, port, transport)
        except Exception:
            hs = {}
        try:
            resumes = _reconnect_resumes(host, port, transport)
        except Exception:
            resumes = None
        try:
            scsv = _supports_fallback_scsv(host, port, transport,
                                           res["protocols"])
        except Exception:
            scsv = None

        accepted = set(res["ciphers"].get("TLSv1.2", [])
                       + res["ciphers"].get("TLSv1.3", []))
        has_rc4 = any("RC4" in c for c in accepted)
        has_3des = any("3DES" in c or "DES-CBC3" in c for c in accepted)
        dhe = any(c.startswith("DHE") or "DHE-" in c for c in accepted)
        ssl3 = bool(res["protocols"].get("SSLv3", {}).get("supported"))
        hdrs = res.get("headers", {})
        res["vuln"] = {
            "secure_renegotiation": hs.get("secure_renegotiation"),
            "client_initiated_reneg": False,   # openssl refuses; server-guarded
            "compression": hs.get("compression"),
            "rc4": has_rc4,
            "3des": has_3des,
            "poodle_ssl3": ssl3,
            "poodle_tls": None,                # needs an active oracle probe
            "goldendoodle": None,
            "zombie_poodle": None,
            "sleeping_poodle": None,
            "openssl_0length": None,
            "downgrade_scsv": scsv,
            "beast": ("mitigated server-side"
                      if res["protocols"].get("TLSv1.2", {}).get("supported")
                      or res["protocols"].get("TLSv1.3", {}).get("supported")
                      else "not mitigated"),
            "compression_crime": hs.get("compression"),
            "heartbleed": None,                # not actively exploited offline
            "heartbeat_ext": None,
            "ticketbleed": None,
            "openssl_ccs": None,               # CVE-2014-0224 (not probed)
            "openssl_padding_oracle": None,    # CVE-2016-2107 (not probed)
            "robot": None,
            "alpn": hs.get("alpn") or [],
            "npn": hs.get("npn"),
            "session_resumption_caching": resumes,
            "session_resumption_tickets": hs.get("session_ticket"),
            "ocsp_stapling": hs.get("ocsp_stapling"),
            "named_group": hs.get("named_group"),
            "server_temp_key": hs.get("server_temp_key"),
            "dhe_suites": dhe,
            "ecdh_reuse": None,
            "pqc": False,
            "ssl2_handshake": False,
            "zero_rtt": None,
            "hpkp": bool(hdrs.get("hpkp")),
            "hpkp_report_only": bool(hdrs.get("hpkp_report_only")),
            "secure_client_reneg": False,
        }

        # ---- weaknesses + forward secrecy ----------------------------------
        sup = {k: v for k, v in res["protocols"].items() if v.get("supported")}
        all_ciphers = ([v.get("cipher", "") for v in sup.values()]
                       + sum(res["ciphers"].values(), []))
        res["forward_secrecy"] = any(c.startswith(("ECDHE", "DHE", "TLS_"))
                                     for c in all_ciphers if c)
        for c in set(all_ciphers):
            if any(w in c for w in WEAK_MARKERS):
                res["weaknesses"].append("weak cipher accepted: %s" % c)

    if res["protocols"].get("SSLv3", {}).get("supported"):
        res["weaknesses"].append("SSLv3 enabled")
    for old in ("TLSv1.0", "TLSv1.1"):
        if res["protocols"].get(old, {}).get("supported"):
            res["weaknesses"].append("%s enabled" % old)
    if res.get("trusted") is False:
        res["weaknesses"].append("chain not trusted by the system CA store")
    if res.get("hostname_match") is False:
        res["weaknesses"].append("hostname does not match certificate CN/SANs")
    if (res.get("cert", {}).get("days_left") is not None
            and res["cert"]["days_left"] < 0):
        res["weaknesses"].append("certificate EXPIRED")
    if res["vuln"].get("compression"):
        res["weaknesses"].append("TLS compression enabled (CRIME)")
    if res["vuln"].get("rc4"):
        res["weaknesses"].append("RC4 cipher accepted")
    if res["vuln"].get("secure_renegotiation") is False:
        res["weaknesses"].append("secure renegotiation not supported")

    res["duration_s"] = round(time.time() - _t0, 1)
    res["grade"], res["grade_reasons"] = _grade(res)
    return res


def _grade(res):
    """SSL-Labs-style letter, conservative subset of their rules."""
    reasons = []
    cert = res.get("cert") or {}
    if res.get("error"):
        return "-", ["probe failed"]
    if (cert.get("days_left") is not None and cert["days_left"] < 0):
        return "F", ["certificate expired"]
    if res.get("hostname_match") is False:
        return "T", ["certificate name mismatch for the tested hostname"]
    if res.get("trusted") is False:
        return "T", ["chain is not trusted by this host's CA store "
                     "(private CA, missing intermediate, or self-signed)"]
    if res["protocols"].get("SSLv3", {}).get("supported"):
        return "F", ["SSLv3 enabled"]
    grade = "A"
    if not (res["protocols"].get("TLSv1.2", {}).get("supported")
            or res["protocols"].get("TLSv1.3", {}).get("supported")):
        return "F", ["no modern TLS protocol available"]
    if any(res["protocols"].get(p, {}).get("supported")
           for p in ("TLSv1.0", "TLSv1.1")):
        grade = "B"
        reasons.append("legacy TLS 1.0/1.1 still enabled → capped at B")
    if any("weak cipher" in w for w in res["weaknesses"]):
        grade = min(grade, "C", key="ABCDEF".index) if grade != "A" else "C"
        reasons.append("weak cipher accepted → capped at C")
    if not res.get("forward_secrecy"):
        grade = "B" if grade == "A" else grade
        reasons.append("no forward-secrecy ciphers → capped at B")
    if res.get("trusted") is None:
        reasons.append("chain trust could not be verified from this host")
    if grade == "A" and res.get("hsts", {}).get("long"):
        grade = "A+"
        reasons.append("TLS 1.2/1.3 only, FS ciphers, long-duration HSTS")
    elif grade == "A":
        reasons.append("TLS 1.2/1.3 only with FS ciphers "
                       "(HSTS < 6 months keeps it at A)")
    return grade, reasons


# ---------------------------------------------------------------------------
# ONLINE — the real online SSL/TLS assessment assessment
# ---------------------------------------------------------------------------

def _api_base():
    return os.environ.get("SSLLABS_API",
                          "https://api.ssllabs.com/api/v3").rstrip("/")


def _api_get(path, params, timeout=30):
    url = _api_base() + path + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={
        "User-Agent": "sslcheck/1.0 (+https://github.com/)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def online_check(host, log=lambda m: None, cancelled=lambda: False,
                 max_wait=600, poll=10, from_cache=True, port=443):
    """Run/fetch the public SSL Labs assessment and summarise it into the
    same shape offline_check produces (plus the raw endpoint data).
    SSL Labs only assesses port 443 — a different requested port is noted."""
    res = {"mode": "online", "target": host, "host": host,
           "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    if port not in (None, 443):
        res["notes"] = ["SSL Labs only assesses port 443 — the requested "
                        "port %s was checked as %s:443 instead; use the "
                        "Offline check for non-standard ports" % (port, host)]
    if _is_ip(host):
        res.setdefault("notes", []).append(
            "SSL Labs assessments work best with hostnames; IP-only targets "
            "may be refused by the API")
    params = {"host": host, "all": "done", "publish": "off"}
    if from_cache:
        params.update(fromCache="on", maxAge=24)
    else:
        params["startNew"] = "on"
    t0 = time.time()
    while True:
        if cancelled():
            res["error"] = "cancelled"
            return res
        try:
            data = _api_get("/analyze", params)
        except Exception as e:
            res["error"] = "SSL Labs API unreachable: %s" % str(e)[:200]
            res["hint"] = ("Could not reach api.ssllabs.com — "
                           "check this host's internet/proxy settings, or "
                           "use the Offline check.")
            res["grade"] = "-"
            return res
        params.pop("startNew", None)          # only on the first call
        status = data.get("status", "")
        log("ssllabs status: %s" % status)
        if status == "READY":
            break
        if status == "ERROR":
            res["error"] = "SSL Labs: %s" % (data.get("statusMessage") or "error")
            res["grade"] = "-"
            return res
        if time.time() - t0 > max_wait:
            res["error"] = ("SSL Labs assessment still running after %ds — "
                            "try again in a few minutes" % max_wait)
            res["grade"] = "-"
            return res
        time.sleep(poll)

    eps = data.get("endpoints") or []
    ep = eps[0] if eps else {}
    det = ep.get("details") or {}
    res["ip"] = ep.get("ipAddress", "")
    res["grade"] = ep.get("grade", "?")
    res["all_endpoints"] = [{"ip": e.get("ipAddress"),
                             "grade": e.get("grade", "?")} for e in eps]
    res["protocols"] = {}
    for p in det.get("protocols") or []:
        res["protocols"]["%s%s" % (p.get("name", ""), (" " + p.get("version", "")).rstrip())] = {
            "supported": True}
    certs = data.get("certs") or []
    if certs:
        c = certs[0]
        res["cert"] = {
            "cn": ", ".join(c.get("commonNames") or []),
            "subject": c.get("subject", ""),
            "sans": c.get("altNames") or [],
            "issuer_cn": c.get("issuerSubject", ""),
            "not_after": time.strftime("%Y-%m-%d",
                                       time.gmtime((c.get("notAfter") or 0) / 1000)),
            "days_left": int(((c.get("notAfter") or 0) / 1000 - time.time()) // 86400),
            "key_type": c.get("keyAlg", ""), "key_bits": c.get("keySize", 0),
            "sig_alg": c.get("sigAlg", ""),
        }
    res["hsts"] = {"present": (det.get("hstsPolicy") or {}).get("status") == "present",
                   "long": ((det.get("hstsPolicy") or {}).get("maxAge") or 0) >= 15552000}
    fs = det.get("forwardSecrecy")
    res["forward_secrecy"] = bool(fs and fs >= 2)
    res["weaknesses"] = []
    if det.get("supportsRc4"):
        res["weaknesses"].append("RC4 supported")
    if det.get("vulnBeast"):
        res["weaknesses"].append("BEAST (mitigation client-side)")
    if det.get("heartbleed"):
        res["weaknesses"].append("Heartbleed VULNERABLE")
    res["grade_reasons"] = ["grade as reported by ssllabs.com"]
    res["raw_summary"] = {"status": data.get("status"),
                          "testTime": data.get("testTime"),
                          "engineVersion": data.get("engineVersion")}
    return res


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------

_GRADE_ORDER = {"A+": 7, "A": 6, "B": 5, "C": 4, "D": 3, "F": 2, "T": 1, "-": 0}


def _c(code, text, on=True):
    return "\033[%sm%s\033[0m" % (code, text) if on else str(text)


def _grade_color(g):
    return {"A+": "1;32", "A": "1;32", "B": "1;33", "C": "1;33"}.get(g, "1;31")


def _fmt_protocols(protocols):
    order = ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3", "SSLv2"]
    bits = []
    for name in order:
        p = (protocols or {}).get(name) or {}
        sup = p.get("supported")
        bits.append("%s %s" % (name, {True: "yes", False: "no",
                                      None: "n/t"}[sup]))
    return " · ".join(bits)


def _render(r, color=True):
    lines = []
    grade = r.get("grade", "-")
    title = "%s " % r.get("target", "?")
    pad = "." * max(3, 58 - len(title) - len(grade))
    lines.append("%s%s grade %s" % (title, pad,
                                    _c(_grade_color(grade), grade, color)))
    ind = "  %-15s %s"
    if r.get("error"):
        lines.append(ind % ("ERROR", r["error"]))
        if r.get("hint"):
            lines.append(ind % ("HINT", r["hint"]))
    if r.get("ip"):
        rdns = (" (%s)" % r["server_hostname"]) if r.get("server_hostname") \
               and r["server_hostname"] != r.get("ip") else ""
        lines.append(ind % ("resolved ip", r["ip"] + rdns))
    if r.get("transport"):
        lines.append(ind % ("probe path", "%s (%s)" % (r["transport"],
                                                       r.get("engine", ""))))
    cert = r.get("cert") or {}
    if cert.get("cn") or cert.get("subject"):
        lines.append(ind % ("certificate", "CN=%s — issued by %s" %
                            (cert.get("cn"), cert.get("issuer_cn"))))
        if cert.get("notafter"):
            lines.append(ind % ("valid until", "%s (%s days)" %
                                (cert.get("notafter"),
                                 cert.get("days_left"))))
        if cert.get("key_type") or cert.get("sig_alg"):
            key = " ".join(str(x) for x in
                           (cert.get("key_type"), cert.get("key_bits"))
                           if x is not None) or "?"
            lines.append(ind % ("key / sig", "%s / %s" %
                                (key, cert.get("sig_alg"))))
        sans = cert.get("sans") or []
        if sans:
            extra = " …" if len(sans) > 6 else ""
            lines.append(ind % ("SANs", ", ".join(sans[:6]) + extra))
    if r.get("protocols"):
        lines.append(ind % ("protocols", _fmt_protocols(r["protocols"])))
        for n in ("TLSv1.3", "TLSv1.2"):
            note = (r["protocols"].get(n) or {}).get("note")
            if note:
                lines.append(ind % ("", "%s: %s" % (n, note)))
    ciphers = r.get("ciphers") or {}
    for proto in ("TLSv1.3", "TLSv1.2"):
        if ciphers.get(proto):
            lines.append(ind % ("%s ciphers" % proto.lower(),
                                ", ".join(ciphers[proto][:6])))
    chain = r.get("chain") or []
    if chain:
        lines.append(ind % ("chain", " <- ".join(c.get("cn") or "?"
                                                 for c in chain)))
    flags = []
    for label, key in (("trusted", "trusted"),
                       ("hostname match", "hostname_match"),
                       ("forward secrecy", "forward_secrecy")):
        v = r.get(key)
        if v is not None:
            flags.append("%s %s" % (label, "yes" if v else
                                    _c("1;31", "NO", color)))
    hsts = (r.get("hsts") or {}).get("present")
    if hsts is not None:
        flags.append("hsts %s" % ("yes" if hsts else "no"))
    if flags:
        lines.append(ind % ("", " · ".join(flags)))
    if r.get("grade_reasons"):
        lines.append(ind % ("grade basis", "; ".join(r["grade_reasons"])))
    for n in r.get("notes") or []:
        lines.append(ind % ("note", n))
    return "\n".join(lines)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="sslcheck",
        description="TLS/SSL report card for any host — offline (local "
                    "openssl, proxy-aware) or online (online SSL/TLS assessment).")
    ap.add_argument("targets", nargs="+",
                    help="hostname, host:port, IP, or full URL")
    ap.add_argument("--online", action="store_true",
                    help="use the public SSL Labs assessment instead of "
                         "probing locally")
    ap.add_argument("--json", action="store_true", dest="as_json",
                    help="print full JSON results")
    ap.add_argument("--proxy", metavar="URL",
                    help="egress proxy for this run (overrides environment;"
                         " http://user:pass@host:port supported)")
    ap.add_argument("--min-grade", metavar="G", choices=sorted(_GRADE_ORDER),
                    help="exit 1 if any target grades below G "
                         "(T and - always fail)")
    ap.add_argument("--expiring", metavar="DAYS", type=int,
                    help="exit 1 if any certificate expires within DAYS")
    ap.add_argument("--no-color", action="store_true",
                    help="disable ANSI colors")
    ap.add_argument("--quiet", action="store_true",
                    help="suppress progress lines on stderr")
    ap.add_argument("--version", action="version",
                    version="sslcheck %s" % __version__)
    args = ap.parse_args(argv)

    if args.proxy:
        os.environ["SSLCHECK_PROXY"] = args.proxy
    color = (not args.no_color) and sys.stdout.isatty()
    log = (lambda m: None) if args.quiet else \
          (lambda m: print("  #", m, file=sys.stderr))

    results, worst = [], 7
    had_error = expiring = below = False
    for raw in args.targets:
        host, port = _normalise_target(raw)
        r = (online_check(host, port=port, log=log) if args.online
             else offline_check(host, port, log=log))
        results.append(r)
        g = r.get("grade", "-")
        worst = min(worst, _GRADE_ORDER.get(g, 0))
        had_error |= bool(r.get("error"))
        days = (r.get("cert") or {}).get("days_left")
        if args.expiring is not None and days is not None \
                and days < args.expiring:
            expiring = True
        if args.min_grade and _GRADE_ORDER.get(g, 0) < \
                _GRADE_ORDER[args.min_grade]:
            below = True

    if args.as_json:
        print(json.dumps(results if len(results) > 1 else results[0],
                         indent=2))
    else:
        print("\n\n".join(_render(r, color) for r in results))

    if had_error:
        return 2
    if below or expiring:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:                    # e.g. `sslcheck … | head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(141)

