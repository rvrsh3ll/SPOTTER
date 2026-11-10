#!/usr/bin/env python3
"""Tiny DNS stub for Site Clone OPSEC resolvers.

Listens on a single IPv4 address (typically a 127.0.0.N loopback) and
forwards queries to the operator's chosen resolvers:

* Plain IPs: classic DNS over UDP/53 (TCP/53 fallback).
* https:// URLs: DNS-over-HTTPS. RFC 8484 (application/dns-message) is
  tried first. Endpoints whose path is /resolve (Google's JSON API) also
  have a JSON fallback. Known /resolve URLs are rewritten to /dns-query
  for the wire-format attempt.
* tls://host[:port]: DNS-over-TLS on port 853.

Debian bookworm has no maintained lightweight DoH stub in main (no
cloudflared, no AdGuard dnsproxy, no doh-client), so this script is the
pinned, in-tree stub. It is started per job and bound only to the loopback
address written into that job's resolv.conf.

Usage:
  python3 site_clone_dns_stub.py --bind 127.0.0.2 --port 53 \\
      --server 77.88.8.8 --server https://dns.google/dns-query \\
      --ready /path/to/ready.flag --pid /path/to/stub.pid
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import socket
import ssl
import struct
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 4.0
MAX_MSG = 4096
# Google's JSON API lives at /resolve; the same host speaks RFC 8484 at /dns-query.
_RESOLVE_TO_WIRE = {
    "https://dns.google/resolve": "https://dns.google/dns-query",
    "https://dns.google/resolve/": "https://dns.google/dns-query",
}


def _is_ip(token: str) -> bool:
    host = token
    if token.startswith("[") and "]" in token:
        host = token[1:token.index("]")]
    elif token.count(":") == 1 and "." in token:
        host = token.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _ip_and_port(token: str, default: int = 53) -> tuple[str, int]:
    t = token.strip()
    if t.startswith("["):
        end = t.index("]")
        host = t[1:end]
        port = default
        if len(t) > end + 1 and t[end + 1] == ":":
            port = int(t[end + 2:])
        return host, port
    if t.count(":") == 1 and "." in t:
        host, port_s = t.rsplit(":", 1)
        return host, int(port_s)
    return t, default


def encode_name(name: str) -> bytes:
    out = bytearray()
    n = (name or "").rstrip(".")
    if n:
        for label in n.split("."):
            raw = label.encode("idna")
            if len(raw) > 63:
                raise ValueError("label too long")
            out.append(len(raw))
            out.extend(raw)
    out.append(0)
    return bytes(out)


def decode_name(buf: bytes, offset: int = 0) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = offset
    hops = 0
    while True:
        if offset >= len(buf):
            raise ValueError("truncated name")
        length = buf[offset]
        if length == 0:
            if not jumped:
                end = offset + 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(buf):
                raise ValueError("truncated pointer")
            ptr = ((length & 0x3F) << 8) | buf[offset + 1]
            if not jumped:
                end = offset + 2
            offset = ptr
            jumped = True
            hops += 1
            if hops > 20:
                raise ValueError("compression loop")
            continue
        offset += 1
        raw = buf[offset:offset + length]
        try:
            labels.append(raw.decode("idna"))
        except UnicodeError:
            labels.append(raw.decode("ascii", errors="replace"))
        offset += length
        if not jumped:
            end = offset
    return ".".join(labels), end


def parse_question(query: bytes) -> tuple[str, int] | None:
    if len(query) < 12:
        return None
    try:
        name, off = decode_name(query, 12)
        if off + 4 > len(query):
            return None
        qtype = struct.unpack("!H", query[off:off + 2])[0]
        return name, qtype
    except Exception:
        return None


def _servfail(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    flags = struct.unpack("!H", query[2:4])[0]
    # QR=1, copy RD, RA=1, RCODE=SERVFAIL (2)
    out_flags = 0x8000 | (flags & 0x0100) | 0x0080 | 0x0002
    return query[:2] + struct.pack("!H", out_flags) + query[4:]


def _forward_udp(query: bytes, host: str, port: int) -> bytes | None:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(TIMEOUT)
        sock.sendto(query, (host, port))
        data, _ = sock.recvfrom(MAX_MSG)
        return data or None
    except OSError:
        return None
    finally:
        sock.close()


def _forward_dot(query: bytes, host: str, port: int) -> bytes | None:
    try:
        ctx = ssl.create_default_context()
        raw = socket.create_connection((host, port), timeout=TIMEOUT)
        tls = ctx.wrap_socket(raw, server_hostname=host)
        try:
            tls.settimeout(TIMEOUT)
            tls.sendall(struct.pack("!H", len(query)) + query)
            hdr = _recv_exact(tls, 2)
            if not hdr:
                return None
            (length,) = struct.unpack("!H", hdr)
            if length <= 0 or length > 16384:
                return None
            return _recv_exact(tls, length)
        finally:
            try:
                tls.close()
            except OSError:
                pass
    except OSError:
        return None


def _recv_exact(sock: ssl.SSLSocket, n: int) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < n:
        try:
            part = sock.recv(n - len(chunks))
        except OSError:
            return None
        if not part:
            return None
        chunks.extend(part)
    return bytes(chunks)


def _doh_wire_url(url: str) -> str:
    key = url.rstrip("/")
    if url in _RESOLVE_TO_WIRE:
        return _RESOLVE_TO_WIRE[url]
    if key in _RESOLVE_TO_WIRE:
        return _RESOLVE_TO_WIRE[key]
    if key.endswith("/resolve"):
        return key[: -len("/resolve")] + "/dns-query"
    return url


def _forward_doh_wire(query: bytes, url: str, user_agent: str) -> bytes | None:
    headers = {
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
        "User-Agent": user_agent or "SPOTTER-site-clone-dns/1",
    }
    req = urllib.request.Request(url, data=query, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            ctype = (resp.headers.get("Content-Type") or "").lower()
            data = resp.read()
            if "dns-message" in ctype or (data and data[:2] == query[:2]):
                return data
            return data if data else None
    except (urllib.error.URLError, OSError, TimeoutError):
        pass
    # RFC 8484 GET with base64url-encoded wire query.
    b64 = base64.urlsafe_b64encode(query).decode("ascii").rstrip("=")
    sep = "&" if "?" in url else "?"
    get_url = url + sep + "dns=" + b64
    req = urllib.request.Request(get_url, method="GET", headers={
        "Accept": "application/dns-message",
        "User-Agent": headers["User-Agent"],
    })
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = resp.read()
            return data or None
    except (urllib.error.URLError, OSError, TimeoutError):
        return None


def _forward_doh_json(query: bytes, url: str, user_agent: str) -> bytes | None:
    parsed = parse_question(query)
    if not parsed:
        return None
    name, qtype = parsed
    sep = "&" if "?" in url else "?"
    get_url = url + sep + "name=" + urllib.parse.quote(name) + "&type=" + str(qtype)
    req = urllib.request.Request(get_url, method="GET", headers={
        "Accept": "application/dns-json",
        "User-Agent": user_agent or "SPOTTER-site-clone-dns/1",
    })
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, TimeoutError, ValueError, UnicodeError):
        return None
    return _json_to_dns(query, name, qtype, payload)


def _encode_rdata(rtype: int, data: str) -> bytes | None:
    if rtype == 1:  # A
        try:
            return ipaddress.IPv4Address(data).packed
        except Exception:
            return None
    if rtype == 28:  # AAAA
        try:
            return ipaddress.IPv6Address(data).packed
        except Exception:
            return None
    if rtype in {2, 5, 12}:  # NS, CNAME, PTR
        try:
            return encode_name(data)
        except Exception:
            return None
    if rtype == 16:  # TXT
        raw = data.encode("utf-8", errors="replace")
        chunks = bytearray()
        for i in range(0, len(raw) or 1, 255):
            part = raw[i:i + 255]
            chunks.append(len(part))
            chunks.extend(part)
        return bytes(chunks)
    return None


def _json_to_dns(query: bytes, qname: str, qtype: int, payload: dict) -> bytes | None:
    if len(query) < 12:
        return None
    answers = payload.get("Answer") or []
    status = int(payload.get("Status") or 0)
    flags = struct.unpack("!H", query[2:4])[0]
    out_flags = 0x8000 | (flags & 0x0100) | 0x0080 | (status & 0x000F)
    records = bytearray()
    ancount = 0
    for ans in answers:
        rtype = int(ans.get("type") or qtype)
        rdata = _encode_rdata(rtype, str(ans.get("data") or ""))
        if rdata is None:
            continue
        ttl = int(ans.get("TTL") or 60)
        try:
            records.extend(encode_name(str(ans.get("name") or qname)))
        except Exception:
            continue
        records.extend(struct.pack("!HHIH", rtype, 1, max(0, ttl), len(rdata)))
        records.extend(rdata)
        ancount += 1
        if ancount >= 32:
            break
    # Question section is copied from the query (from byte 12 through the question).
    q = parse_question(query)
    if not q:
        return None
    _, q_end = decode_name(query, 12)
    q_end += 4
    header = query[:2] + struct.pack("!H", out_flags) + struct.pack("!HHHH", 1, ancount, 0, 0)
    return header + query[12:q_end] + bytes(records)


def forward_query(query: bytes, servers: list[str], user_agent: str = "") -> bytes:
    for token in servers:
        data = None
        if token.startswith("https://"):
            wire = _doh_wire_url(token)
            data = _forward_doh_wire(query, wire, user_agent)
            if not data and ("/resolve" in token or wire != token):
                data = _forward_doh_json(query, token, user_agent)
        elif token.startswith("tls://"):
            hostport = token[len("tls://"):]
            host, port = _ip_and_port(hostport, 853) if False else _split_host(hostport, 853)
            data = _forward_dot(query, host, port)
        elif _is_ip(token):
            host, port = _ip_and_port(token, 53)
            data = _forward_udp(query, host, port)
        if data:
            return data
    return _servfail(query)


def _split_host(hostport: str, default: int) -> tuple[str, int]:
    if hostport.startswith("["):
        return _ip_and_port(hostport, default)
    if ":" in hostport and hostport.rsplit(":", 1)[-1].isdigit():
        host, port_s = hostport.rsplit(":", 1)
        return host, int(port_s)
    return hostport, default


class _Handler:
    def __init__(self, servers: list[str], user_agent: str):
        self.servers = servers
        self.user_agent = user_agent

    def handle(self, data: bytes) -> bytes:
        return forward_query(data, self.servers, self.user_agent)


def serve(bind: str, port: int, servers: list[str], ready_path: str = "",
          pid_path: str = "", user_agent: str = "") -> None:
    handler = _Handler(servers, user_agent)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind((bind, port))
    udp.settimeout(0.5)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((bind, port))
    tcp.listen(8)
    tcp.settimeout(0.5)
    if pid_path:
        with open(pid_path, "w", encoding="utf-8") as fh:
            fh.write(str(os.getpid()))
    if ready_path:
        with open(ready_path, "w", encoding="utf-8") as fh:
            fh.write("ready\n")

    def tcp_one(conn: socket.socket) -> None:
        try:
            conn.settimeout(TIMEOUT)
            hdr = conn.recv(2)
            if len(hdr) < 2:
                return
            (length,) = struct.unpack("!H", hdr)
            if length <= 0 or length > 16384:
                return
            chunks = bytearray()
            while len(chunks) < length:
                part = conn.recv(length - len(chunks))
                if not part:
                    return
                chunks.extend(part)
            answer = handler.handle(bytes(chunks))
            if answer:
                conn.sendall(struct.pack("!H", len(answer)) + answer)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    try:
        while True:
            try:
                data, addr = udp.recvfrom(MAX_MSG)
                if data:
                    answer = handler.handle(data)
                    if answer:
                        udp.sendto(answer, addr)
            except socket.timeout:
                pass
            except OSError:
                break
            try:
                conn, _ = tcp.accept()
                threading.Thread(target=tcp_one, args=(conn,), daemon=True).start()
            except socket.timeout:
                pass
            except OSError:
                break
    finally:
        udp.close()
        tcp.close()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Per-job DNS/DoH stub for Site Clone")
    p.add_argument("--bind", required=True, help="IPv4 address to listen on")
    p.add_argument("--port", type=int, default=53)
    p.add_argument("--server", action="append", default=[], dest="servers",
                   help="Upstream resolver (IP, https:// DoH URL, or tls:// host). Repeatable.")
    p.add_argument("--ready", default="", help="Path written once the socket is bound")
    p.add_argument("--pid", default="", help="Path written with the stub PID")
    p.add_argument("--user-agent", default="", dest="user_agent")
    args = p.parse_args(argv)
    if not args.servers:
        print("at least one --server is required", file=sys.stderr)
        return 2
    try:
        serve(args.bind, args.port, args.servers, args.ready, args.pid, args.user_agent)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
