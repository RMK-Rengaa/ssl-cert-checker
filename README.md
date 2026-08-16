# sslcheck

A TLS/SSL checker that works even where the network fights back.

Point it at any hostname, IP, or full URL and get an SSL-Labs-style report
card: protocol matrix (SSLv3 → TLS 1.3), negotiated ciphers, the full served
chain, trust + hostname verification, days to expiry, HSTS, forward secrecy,
ALPN, common weaknesses, and a letter grade (**A+ / A / B / C / D / F / T / -**).

Born from a real problem: on servers inside corporate networks, every local
TLS tool dies with `write:errno=104` because an egress firewall resets the
handshake — while browser-based checkers work fine. sslcheck closes that gap.

**Pure stdlib + the `openssl` binary. No third-party packages. One file.**

## Why it's different

1. **Transport auto-selection.** Every run first tries a direct connection.
   If the direct TLS handshake is blocked (firewall RST, timeout, no route)
   and an egress proxy is configured — `SSLCHECK_PROXY` or the standard
   `https_proxy` / `all_proxy` variables, honouring `no_proxy` — the whole
   run transparently switches to `openssl s_client -proxy` (HTTP CONNECT)
   and stays there, so every number in the report comes from one coherent
   path. Loopback and `no_proxy` hosts are never proxied.

2. **Python-ssl rescue engine.** If openssl can't complete a handshake on
   either transport — missing binary, local security policy, or a proxy that
   requires Basic authentication (which `s_client -proxy` cannot speak) —
   the probe is redone with Python's own `ssl` module through a manual
   CONNECT tunnel. You still get the leaf certificate, protocol matrix,
   ALPN, and trust/hostname verdicts instead of a bare error.

3. **Honest diagnostics.** A blocked or reset probe is reported as
   **not testable (n/t)** — never as protocol "no". Errors come with a
   plain-language diagnosis and a hint naming the next step. Every result
   states which transport and engine produced it. If the certificate name
   matches but the chain anchors to a private root, the report says so:
   TLS-intercepting middleboxes (corporate SSL inspection) are *detected*,
   not mistaken for broken sites.

4. **URLs just work.** `https://example.com/some/path` targets
   `example.com:443`, like every public SSL tester. An explicit port
   (`host:8443`, `http://host:8080/x`) is always respected.

## Install

```bash
curl -O https://raw.githubusercontent.com/<you>/<repo>/main/sslcheck.py
python3 sslcheck.py example.com
```

Requires Python 3.8+ and the `openssl` binary (present on virtually every
Linux/macOS system; the Python rescue engine covers hosts without it).

## Usage

```bash
# report card for one or more targets (hostname, host:port, IP, or URL)
python3 sslcheck.py example.com
python3 sslcheck.py https://example.com/any/path other.example:8443

# full JSON (for scripts / jq)
python3 sslcheck.py example.com --json

# use the public online SSL/TLS assessment assessment instead of probing locally
python3 sslcheck.py example.com --online

# behind an egress proxy (or export https_proxy / SSLCHECK_PROXY instead)
python3 sslcheck.py example.com --proxy http://proxy.corp:3128
python3 sslcheck.py example.com --proxy http://user:pass@proxy.corp:3128

# monitoring / CI: fail the build on weak TLS or a soon-to-expire cert
python3 sslcheck.py api.example.com --min-grade B --expiring 30 --quiet
```

Exit codes: `0` all good · `1` a `--min-grade` / `--expiring` policy failed
· `2` a probe errored (unreachable, no TLS, …).

Example output:

```
www.example.com:443 ................................ grade A+
  resolved ip     93.184.216.34
  probe path      direct (openssl)
  certificate     CN=www.example.com — issued by DigiCert TLS RSA SHA256 2020 CA1
  valid until     2027-01-24 (160 days)
  key / sig       RSA 2048 / SHA256withRSA
  protocols       TLSv1.3 yes · TLSv1.2 yes · TLSv1.1 n/t · TLSv1.0 n/t · SSLv3 n/t · SSLv2 no
  tlsv1.3 ciphers TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
  chain           www.example.com <- DigiCert TLS RSA SHA256 2020 CA1
                  trusted yes · hostname match yes · forward secrecy yes · hsts yes
```

## Library

```python
from sslcheck import offline_check, online_check

r = offline_check("example.com")          # or ("host", 8443)
print(r["grade"], r["cert"]["days_left"], r["protocols"]["TLSv1.3"])

r = online_check("example.com")           # online SSL/TLS assessment, same shape
```

Both return the same dict shape: `grade`, `grade_reasons`, `cert` (cn, sans,
issuer, validity, key), `chain`, `protocols` (per-protocol
`supported: true/false/null` + note), `ciphers`, `trusted`,
`hostname_match`, `forward_secrecy`, `hsts`, `vuln`, `transport`, `engine`,
`notes`, and on failure `error` + `hint`.

## Grades

SSL-Labs-style: **A+/A** modern TLS only (1.2/1.3) with forward secrecy
(A+ needs long-max-age HSTS) · **B/C/D/F** progressively for legacy
protocols, weak ciphers/keys, or expired certs · **T** the chain is not
trusted by *this host's* CA store (self-signed, private CA, or a
TLS-inspecting middlebox — the notes tell you which) · **-** the probe
could not complete (the error and hint tell you why).

`n/t` (not testable) in the protocol matrix means the probe was blocked or
this host's OpenSSL refuses to speak that legacy protocol — reported
honestly instead of guessed. A remote assessment (`--online`) can test what
a local one can't.

## Testing

```bash
python3 test_sslcheck.py -v
```

15 hermetic tests — no internet needed. They spin up a local TLS server, a
firewall-style RST listener, and a real HTTP CONNECT proxy (with and
without auth) to exercise the transport fallback, the Python rescue engine,
the diagnostics, and the grader.

## License

MIT — see [LICENSE](LICENSE).

