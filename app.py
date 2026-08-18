"""icmp-test: does a Cloud in a Bottle app get to use ICMP?

A single-file diagnostic web app. It answers three questions empirically, from
inside an app container:

  1. Can the app *send* an ICMP echo request and *receive* the echo reply?
     Tested three independent ways: an ICMP datagram ("ping") socket, an
     AF_INET/SOCK_RAW socket, and the system ``ping`` binary. Each is also
     re-run as an unprivileged uid/gid to show how much of the answer depends
     on the container's user.
  2. Does *non-echo* ICMP (time-exceeded, dest-unreachable) reach the app?
     That is what traceroute/mtr and PMTU discovery need.
  3. Can anything *outside* deliver an ICMP echo request *to* the app? A
     background sniffer records every ICMP packet the container's network
     namespace receives, so an operator can ping the instance from elsewhere
     and then read back what (if anything) arrived.

Everything is also exposed as JSON so it can be driven from a script, and the
probes can be run directly from the command line (``--probe``), which is how
the unprivileged variants are executed via ``setpriv``.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import platform
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

PORT = int(os.environ.get("PORT", "5000"))

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACH = 3
ICMP_TIME_EXCEEDED = 11
ICMPV6_ECHO_REQUEST = 128
ICMPV6_ECHO_REPLY = 129

ICMP_TYPE_NAMES = {
    0: "echo-reply",
    3: "destination-unreachable",
    5: "redirect",
    8: "echo-request",
    11: "time-exceeded",
    12: "parameter-problem",
    13: "timestamp-request",
    14: "timestamp-reply",
}
ICMPV6_TYPE_NAMES = {
    1: "destination-unreachable",
    2: "packet-too-big",
    3: "time-exceeded",
    4: "parameter-problem",
    128: "echo-request",
    129: "echo-reply",
    135: "neighbor-solicitation",
    136: "neighbor-advertisement",
}

# Probe targets. Public resolvers plus a hostname, so DNS and ICMP are
# distinguishable failures.
DEFAULT_TARGETS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "one.one.one.one"]

# The uid/gid the "unprivileged" variants run as (nobody/nogroup on Debian).
UNPRIV_UID = 65534
UNPRIV_GID = 65534


# ---------------------------------------------------------------------------
# ICMP packet helpers
# ---------------------------------------------------------------------------


def checksum(data: bytes) -> int:
    """Standard RFC 1071 internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total = (total >> 16) + (total & 0xFFFF)
    return ~total & 0xFFFF


def build_echo_request(ident: int, seq: int, payload: bytes, v6: bool) -> bytes:
    """Build an ICMP(v6) echo request.

    For ICMPv6 the kernel recomputes the checksum (it needs the pseudo-header),
    and for IPv4 ping sockets the kernel rewrites both the id and the checksum;
    we fill it in anyway so the raw-socket path is correct.
    """
    icmp_type = ICMPV6_ECHO_REQUEST if v6 else ICMP_ECHO_REQUEST
    header = struct.pack("!BBHHH", icmp_type, 0, 0, ident, seq)
    csum = checksum(header + payload)
    header = struct.pack("!BBHHH", icmp_type, 0, csum, ident, seq)
    return header + payload


def type_name(icmp_type: int, v6: bool) -> str:
    table = ICMPV6_TYPE_NAMES if v6 else ICMP_TYPE_NAMES
    return table.get(icmp_type, f"type-{icmp_type}")


def parse_icmp(data: bytes, *, v6: bool, strip_ip_header: bool) -> dict[str, Any]:
    """Parse a received packet into a description of the ICMP message.

    ``strip_ip_header`` is true only for AF_INET/SOCK_RAW, which is the one case
    where the kernel hands up the IPv4 header as well.
    """
    out: dict[str, Any] = {}
    body = data
    if strip_ip_header and not v6:
        if len(data) < 20:
            return {"error": f"short packet ({len(data)} bytes)"}
        ihl = (data[0] & 0x0F) * 4
        out["ip_ttl"] = data[8]
        out["ip_src"] = socket.inet_ntoa(data[12:16])
        out["ip_dst"] = socket.inet_ntoa(data[16:20])
        body = data[ihl:]
    if len(body) < 8:
        return {"error": f"short ICMP message ({len(body)} bytes)"}
    icmp_type, code, csum, ident, seq = struct.unpack("!BBHHH", body[:8])
    out.update(
        {
            "type": icmp_type,
            "type_name": type_name(icmp_type, v6),
            "code": code,
            "checksum": csum,
            "id": ident,
            "seq": seq,
            "payload_len": len(body) - 8,
            "payload_head": body[8:24].hex(),
        }
    )
    # For error messages the id/seq fields are meaningless; the quoted original
    # datagram follows the 8-byte header instead.
    error_types = (
        {1, 2, 3, 4} if v6 else {ICMP_DEST_UNREACH, ICMP_TIME_EXCEEDED, 12}
    )
    if icmp_type in error_types:
        out.pop("id", None)
        out.pop("seq", None)
        out["quoted"] = body[8:36].hex()
    return out


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


@dataclass
class ProbeResult:
    name: str
    ok: bool
    detail: str
    replies: list[dict[str, Any]] = field(default_factory=list)
    rtt_ms: list[float] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "detail": self.detail,
            "replies": self.replies,
            "rtt_ms": [round(v, 3) for v in self.rtt_ms],
            **({"extra": self.extra} if self.extra else {}),
        }


def resolve(target: str, v6: bool) -> tuple[str | None, str]:
    family = socket.AF_INET6 if v6 else socket.AF_INET
    try:
        infos = socket.getaddrinfo(target, None, family, socket.SOCK_RAW)
    except OSError as exc:
        return None, f"DNS resolution failed: {exc}"
    if not infos:
        return None, "DNS resolution returned no records"
    return infos[0][4][0], ""


def socket_probe(
    target: str,
    *,
    mode: str,
    count: int = 3,
    timeout: float = 3.0,
    payload_size: int = 32,
    ttl: int | None = None,
    v6: bool = False,
) -> ProbeResult:
    """Send echo requests over a Python socket and collect the replies.

    ``mode`` is "dgram" for an ICMP datagram (ping) socket -- allowed without
    CAP_NET_RAW when the caller's gid is inside net.ipv4.ping_group_range -- or
    "raw" for SOCK_RAW, which requires CAP_NET_RAW.
    """
    label = f"{mode}-socket{'-v6' if v6 else ''}"
    if ttl is not None:
        label += f"-ttl{ttl}"

    addr, err = resolve(target, v6)
    if addr is None:
        return ProbeResult(label, False, err)

    family = socket.AF_INET6 if v6 else socket.AF_INET
    proto = socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP
    sock_type = socket.SOCK_DGRAM if mode == "dgram" else socket.SOCK_RAW

    try:
        sock = socket.socket(family, sock_type, proto)
    except OSError as exc:
        return ProbeResult(
            label,
            False,
            f"socket({'AF_INET6' if v6 else 'AF_INET'}, "
            f"{'SOCK_DGRAM' if mode == 'dgram' else 'SOCK_RAW'}, "
            f"{'IPPROTO_ICMPV6' if v6 else 'IPPROTO_ICMP'}) failed: "
            f"[errno {exc.errno}] {exc.strerror}",
            extra={"errno": exc.errno, "resolved": addr},
        )

    result = ProbeResult(label, False, "", extra={"resolved": addr})
    try:
        if ttl is not None:
            if v6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
            else:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        ident = os.getpid() & 0xFFFF
        payload_prefix = b"ciab-icmp-test:"
        sent = 0
        errors: list[str] = []

        for seq in range(1, count + 1):
            payload = (payload_prefix + b"x" * payload_size)[:payload_size]
            packet = build_echo_request(ident, seq, payload, v6)
            start = time.monotonic()
            try:
                sock.sendto(packet, (addr, 0))
            except OSError as exc:
                errors.append(f"seq {seq}: sendto failed: [errno {exc.errno}] {exc.strerror}")
                continue
            sent += 1

            deadline = start + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                readable, _, _ = select.select([sock], [], [], remaining)
                if not readable:
                    break
                data, src = sock.recvfrom(2048)
                elapsed_ms = (time.monotonic() - start) * 1000.0
                parsed = parse_icmp(data, v6=v6, strip_ip_header=(mode == "raw"))
                parsed["from"] = src[0]
                parsed["rtt_ms"] = round(elapsed_ms, 3)
                reply_type = ICMPV6_ECHO_REPLY if v6 else ICMP_ECHO_REPLY
                is_reply = parsed.get("type") == reply_type
                # A raw socket sees every ICMP packet in the namespace, so it
                # must filter on our own id. A ping socket is demultiplexed by
                # the kernel, which also rewrites the id, so we cannot match on
                # it there.
                if mode == "raw" and is_reply and parsed.get("id") != ident:
                    continue
                result.replies.append(parsed)
                if is_reply:
                    result.rtt_ms.append(elapsed_ms)
                    break
                # Non-echo (error) ICMP is interesting in its own right: keep
                # reading in case the real reply is behind it.

        echo_replies = sum(
            1
            for r in result.replies
            if r.get("type") == (ICMPV6_ECHO_REPLY if v6 else ICMP_ECHO_REPLY)
        )
        result.ok = echo_replies > 0
        parts = [f"sent {sent}/{count}", f"echo replies {echo_replies}"]
        other = len(result.replies) - echo_replies
        if other:
            parts.append(f"other ICMP {other}")
        if result.rtt_ms:
            parts.append(f"avg {sum(result.rtt_ms) / len(result.rtt_ms):.2f} ms")
        if errors:
            parts.extend(errors)
        result.detail = ", ".join(parts)
        return result
    finally:
        sock.close()


def run_cmd(cmd: list[str], timeout: float = 25.0) -> dict[str, Any]:
    if shutil.which(cmd[0]) is None:
        return {"cmd": " ".join(cmd), "error": f"{cmd[0]} not found"}
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return {"cmd": " ".join(cmd), "error": f"timed out after {timeout}s"}
    return {
        "cmd": " ".join(cmd),
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }


def ping_binary_probe(
    target: str, *, count: int = 3, v6: bool = False, unprivileged: bool = False
) -> ProbeResult:
    """Run the system ``ping``, optionally after dropping to an unprivileged uid."""
    label = f"ping-binary{'-v6' if v6 else ''}{'-unprivileged' if unprivileged else ''}"
    cmd = ["ping", "-n", "-c", str(count), "-W", "2", "-i", "0.3"]
    cmd.append("-6" if v6 else "-4")
    cmd.append(target)
    if unprivileged:
        cmd = [
            "setpriv",
            f"--reuid={UNPRIV_UID}",
            f"--regid={UNPRIV_GID}",
            "--clear-groups",
        ] + cmd
    info = run_cmd(cmd)
    ok = info.get("returncode") == 0 and " 0% packet loss" in info.get("stdout", "")
    detail = info.get("error") or (info.get("stdout") or "").splitlines()
    if isinstance(detail, list):
        detail = " | ".join(detail[-3:]) if detail else (info.get("stderr") or "no output")
    return ProbeResult(label, ok, str(detail), extra=info)


def unprivileged_socket_probe(target: str, *, mode: str, count: int = 3) -> ProbeResult:
    """Re-exec this file under ``setpriv`` to probe as a non-root uid/gid.

    This is the interesting case for real apps: podman's default
    ``net.ipv4.ping_group_range=0 0`` limits ICMP datagram sockets to gid 0, and
    dropping the uid also drops permitted capabilities, so CAP_NET_RAW no longer
    applies to a plain SOCK_RAW open.
    """
    label = f"{mode}-socket-unprivileged"
    cmd = [
        "setpriv",
        f"--reuid={UNPRIV_UID}",
        f"--regid={UNPRIV_GID}",
        "--clear-groups",
        sys.executable,
        os.path.abspath(__file__),
        "--probe",
        "--mode",
        mode,
        "--target",
        target,
        "--count",
        str(count),
    ]
    info = run_cmd(cmd)
    if "error" in info or info.get("returncode") != 0:
        return ProbeResult(
            label,
            False,
            info.get("error") or info.get("stderr") or "child failed",
            extra=info,
        )
    try:
        payload = json.loads(info["stdout"])
    except (json.JSONDecodeError, KeyError) as exc:
        return ProbeResult(label, False, f"could not parse child output: {exc}", extra=info)
    return ProbeResult(
        label,
        bool(payload.get("ok")),
        str(payload.get("detail", "")),
        replies=payload.get("replies", []),
        rtt_ms=payload.get("rtt_ms", []),
        extra={"child_uid": UNPRIV_UID, "child_gid": UNPRIV_GID},
    )


# ---------------------------------------------------------------------------
# Inbound ICMP sniffer
# ---------------------------------------------------------------------------


class Sniffer:
    """Records every ICMP packet delivered into the container's namespace.

    Used to answer "can something outside ping this app": ping the instance from
    elsewhere, then read /api/sniffer and look for echo-requests.
    """

    def __init__(self, v6: bool = False) -> None:
        self.v6 = v6
        self.packets: list[dict[str, Any]] = []
        self.error: str | None = None
        self.started_at: float | None = None
        self.lock = threading.Lock()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        family = socket.AF_INET6 if self.v6 else socket.AF_INET
        proto = socket.IPPROTO_ICMPV6 if self.v6 else socket.IPPROTO_ICMP
        try:
            sock = socket.socket(family, socket.SOCK_RAW, proto)
        except OSError as exc:
            self.error = f"raw socket for sniffing failed: [errno {exc.errno}] {exc.strerror}"
            return
        self.started_at = time.time()
        with sock:
            while True:
                try:
                    readable, _, _ = select.select([sock], [], [], 1.0)
                    if not readable:
                        continue
                    data, src = sock.recvfrom(4096)
                except OSError as exc:
                    self.error = f"recv failed: {exc}"
                    return
                parsed = parse_icmp(data, v6=self.v6, strip_ip_header=not self.v6)
                parsed["from"] = src[0]
                parsed["at"] = round(time.time(), 3)
                with self.lock:
                    self.packets.append(parsed)
                    # Keep the tail; a busy namespace should not grow unbounded.
                    if len(self.packets) > 500:
                        del self.packets[:-500]

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            packets = list(self.packets)
        echo_requests = [p for p in packets if p.get("type") == (128 if self.v6 else 8)]
        return {
            "family": "ipv6" if self.v6 else "ipv4",
            "error": self.error,
            "running": self.error is None and self.started_at is not None,
            "started_at": self.started_at,
            "uptime_s": round(time.time() - self.started_at, 1) if self.started_at else None,
            "packets_seen": len(packets),
            "inbound_echo_requests": len(echo_requests),
            "recent": packets[-40:],
        }


SNIFFER = Sniffer()


# ---------------------------------------------------------------------------
# Environment diagnostics
# ---------------------------------------------------------------------------


def read_file(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read().strip()
    except OSError as exc:
        return f"<unreadable: {exc}>"


def environment() -> dict[str, Any]:
    status_keys = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "Seccomp", "NoNewPrivs")
    caps = {}
    for line in read_file("/proc/self/status").splitlines():
        key, _, value = line.partition(":")
        if key in status_keys:
            caps[key] = value.strip()
    try:
        groups = os.getgroups()
    except OSError:
        groups = []
    return {
        "hostname": socket.gethostname(),
        "kernel": platform.platform(),
        "python": sys.version.split()[0],
        "uid": os.getuid(),
        "euid": os.geteuid(),
        "gid": os.getgid(),
        "groups": groups,
        "proc_self_status": caps,
        "capsh": run_cmd(["capsh", "--print"]).get("stdout", ""),
        "ping_group_range": read_file("/proc/sys/net/ipv4/ping_group_range"),
        "ip_unprivileged_port_start": read_file("/proc/sys/net/ipv4/ip_unprivileged_port_start"),
        "getcap_ping": run_cmd(["getcap", "-r", "/usr/bin/ping", "/bin/ping"]).get("stdout", ""),
        "ip_addr": run_cmd(["ip", "-o", "addr"]).get("stdout", ""),
        "ip_route": run_cmd(["ip", "route"]).get("stdout", ""),
        "resolv_conf": read_file("/etc/resolv.conf"),
        "openhost_env": {
            k: v
            for k, v in sorted(os.environ.items())
            if k.startswith(("OPENHOST_", "CIAB_", "BOTTLE_"))
            and "SECRET" not in k
            and "TOKEN" not in k
            and "KEY" not in k
        },
    }


def suite(targets: list[str] | None = None, *, count: int = 3) -> dict[str, Any]:
    """The full outbound/inbound matrix."""
    targets = targets or DEFAULT_TARGETS
    primary = targets[0]
    results: list[ProbeResult] = []

    # 1. Outbound echo, three mechanisms, as the container's own user.
    for target in targets:
        results.append(socket_probe(target, mode="dgram", count=count))
    results.append(socket_probe(primary, mode="raw", count=count))
    results.append(ping_binary_probe(primary, count=count))

    # 2. The same, but unprivileged: this is where podman's
    #    ping_group_range=0 0 default bites apps that set a non-root USER.
    results.append(unprivileged_socket_probe(primary, mode="dgram", count=count))
    results.append(unprivileged_socket_probe(primary, mode="raw", count=count))
    results.append(ping_binary_probe(primary, count=count, unprivileged=True))

    # 3. IPv6.
    results.append(socket_probe("2606:4700:4700::1111", mode="dgram", count=count, v6=True))
    results.append(socket_probe("2606:4700:4700::1111", mode="raw", count=count, v6=True))
    results.append(ping_binary_probe("2606:4700:4700::1111", count=count, v6=True))

    # 4. Non-echo ICMP: a TTL-limited echo should draw a time-exceeded from the
    #    first hop. If nothing comes back, ICMP error messages are not being
    #    delivered into the namespace (no traceroute, no PMTU feedback).
    results.append(socket_probe(primary, mode="dgram", count=1, ttl=1, timeout=4.0))
    results.append(socket_probe(primary, mode="raw", count=1, ttl=1, timeout=4.0))
    results.append(
        ProbeResult(
            "ping-binary-ttl1",
            False,
            "",
            extra=run_cmd(["ping", "-n", "-c", "1", "-W", "3", "-t", "1", primary]),
        )
    )
    ttl_info = results[-1].extra
    ttl_out = (ttl_info.get("stdout", "") or "") + (ttl_info.get("stderr", "") or "")
    results[-1].ok = "Time to live exceeded" in ttl_out or "exceeded" in ttl_out.lower()
    results[-1].detail = " | ".join(ttl_out.splitlines()[:4]) or ttl_info.get("error", "no output")

    # 5. Unreachable-port ICMP: a UDP probe to a closed port on a live host
    #    should draw destination-unreachable.
    results.append(
        ProbeResult(
            "traceroute-icmp",
            False,
            "",
            extra=run_cmd(["traceroute", "-I", "-n", "-m", "4", "-w", "2", primary], timeout=30),
        )
    )
    tr_info = results[-1].extra
    tr_out = tr_info.get("stdout", "") or ""
    # A hop line that is not all stars means ICMP replies/errors made it back.
    hop_lines = [ln for ln in tr_out.splitlines()[1:] if ln.strip()]
    results[-1].ok = any("* * *" not in ln for ln in hop_lines)
    results[-1].detail = " | ".join(hop_lines[:6]) or tr_info.get("error", "no output")

    outbound = [r for r in results if r.name.startswith(("dgram", "raw", "ping-binary")) and "ttl" not in r.name]
    return {
        "generated_at": time.time(),
        "verdict": {
            "outbound_echo_works": any(r.ok for r in outbound),
            "outbound_echo_works_unprivileged": any(
                r.ok for r in results if "unprivileged" in r.name
            ),
            "icmp_errors_delivered": any(r.ok for r in results if "ttl" in r.name or r.name == "traceroute-icmp"),
            "inbound_echo_requests_seen": SNIFFER.snapshot()["inbound_echo_requests"],
        },
        "probes": [r.as_dict() for r in results],
        "sniffer": SNIFFER.snapshot(),
        "environment": environment(),
    }


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

PAGE_CSS = """
body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin: 2rem auto;
       max-width: 60rem; line-height: 1.45; color: #111; }
h1 { font-size: 1.4rem; } h2 { font-size: 1.05rem; margin-top: 2rem; }
table { border-collapse: collapse; width: 100%; font-size: 0.85rem; }
th, td { text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid #ddd;
         vertical-align: top; }
.ok { color: #0a7d28; font-weight: bold; } .bad { color: #b00020; font-weight: bold; }
pre { background: #f5f5f5; padding: 0.75rem; overflow-x: auto; font-size: 0.78rem; }
.verdict { padding: 0.75rem 1rem; background: #f0f4ff; border-left: 4px solid #3355cc; }
a { color: #3355cc; }
"""


def render_html(data: dict[str, Any]) -> str:
    verdict = data["verdict"]

    def mark(value: bool) -> str:
        return '<span class="ok">YES</span>' if value else '<span class="bad">NO</span>'

    rows = []
    for probe in data["probes"]:
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                html.escape(probe["name"]),
                mark(probe["ok"]),
                html.escape(probe["detail"])[:400],
            )
        )
    sniff = data["sniffer"]
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>icmp-test</title><style>{PAGE_CSS}</style></head>
<body>
<h1>icmp-test &mdash; can this app use ICMP?</h1>
<div class="verdict">
<p>Outbound ICMP echo (as the container user): {mark(verdict["outbound_echo_works"])}</p>
<p>Outbound ICMP echo as an unprivileged uid/gid: {mark(verdict["outbound_echo_works_unprivileged"])}</p>
<p>Non-echo ICMP (errors, traceroute) delivered: {mark(verdict["icmp_errors_delivered"])}</p>
<p>Inbound echo requests observed by the sniffer: <b>{verdict["inbound_echo_requests_seen"]}</b>
(sniffer up {sniff["uptime_s"]}s, {sniff["packets_seen"]} ICMP packets seen in total)</p>
</div>
<h2>Probes</h2>
<table><tr><th>probe</th><th>ok</th><th>detail</th></tr>{"".join(rows)}</table>
<h2>Sniffer (inbound ICMP into this container's netns)</h2>
<pre>{html.escape(json.dumps(sniff, indent=2))}</pre>
<h2>Environment</h2>
<pre>{html.escape(json.dumps(data["environment"], indent=2))}</pre>
<h2>JSON endpoints</h2>
<ul>
<li><a href="/api/suite">/api/suite</a> &mdash; everything above as JSON</li>
<li><a href="/api/ping?target=1.1.1.1&amp;mode=dgram">/api/ping?target=&amp;mode=dgram|raw|binary&amp;count=&amp;ttl=&amp;v6=1</a></li>
<li><a href="/api/sniffer">/api/sniffer</a> &mdash; inbound ICMP seen so far</li>
<li><a href="/api/env">/api/env</a> &mdash; caps, sysctls, interfaces</li>
<li><a href="/health">/health</a></li>
</ul>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "icmp-test/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload: Any, status: int = 200) -> None:
        self._send(status, json.dumps(payload, indent=2).encode(), "application/json")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)

        def arg(name: str, default: str) -> str:
            return (query.get(name) or [default])[0]

        if path == "/health":
            self._send(200, b"ok\n", "text/plain")
            return
        if path == "/api/env":
            self._json(environment())
            return
        if path == "/api/sniffer":
            self._json(SNIFFER.snapshot())
            return
        if path == "/api/ping":
            target = arg("target", DEFAULT_TARGETS[0])
            mode = arg("mode", "dgram")
            v6 = arg("v6", "0") not in ("0", "", "false")
            try:
                count = max(1, min(10, int(arg("count", "3"))))
                ttl_raw = arg("ttl", "")
                ttl = int(ttl_raw) if ttl_raw else None
            except ValueError:
                self._json({"error": "count and ttl must be integers"}, 400)
                return
            if mode == "binary":
                result = ping_binary_probe(target, count=count, v6=v6)
            elif mode in ("dgram", "raw"):
                result = socket_probe(target, mode=mode, count=count, ttl=ttl, v6=v6)
            elif mode in ("dgram-unprivileged", "raw-unprivileged"):
                result = unprivileged_socket_probe(
                    target, mode=mode.split("-")[0], count=count
                )
            elif mode == "binary-unprivileged":
                result = ping_binary_probe(target, count=count, v6=v6, unprivileged=True)
            else:
                self._json({"error": f"unknown mode: {mode}"}, 400)
                return
            self._json(result.as_dict())
            return
        if path in ("/api/suite", "/"):
            targets_raw = arg("targets", "")
            targets = [t for t in targets_raw.split(",") if t] or None
            try:
                count = max(1, min(10, int(arg("count", "3"))))
            except ValueError:
                self._json({"error": "count must be an integer"}, 400)
                return
            data = suite(targets, count=count)
            if path == "/":
                self._send(200, render_html(data).encode(), "text/html; charset=utf-8")
            else:
                self._json(data)
            return
        self._json({"error": "not found", "path": self.path}, 404)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="store_true", help="run one probe, print JSON, exit")
    parser.add_argument("--mode", default="dgram", choices=["dgram", "raw"])
    parser.add_argument("--target", default=DEFAULT_TARGETS[0])
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--ttl", type=int, default=None)
    parser.add_argument("--v6", action="store_true")
    args = parser.parse_args()

    if args.probe:
        result = socket_probe(
            args.target, mode=args.mode, count=args.count, ttl=args.ttl, v6=args.v6
        )
        print(json.dumps(result.as_dict()))
        return 0

    SNIFFER.start()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"icmp-test listening on 0.0.0.0:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
