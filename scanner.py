#!/usr/bin/env python3
"""
scanner.py — Async TCP port scanner with service detection and banner grabbing.

Usage examples:
    python3 scanner.py --target 192.168.1.1 --ports 1-1024
    python3 scanner.py --target 10.0.0.0/24 --top-ports 100 --threads 500
    python3 scanner.py --target 192.168.1.1,192.168.1.2 --ports 22,80,443 --format json
    sudo python3 scanner.py --target 192.168.1.1 --ports 1-1024 --syn
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import io
import ipaddress
import json
import os
import platform
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import TextIO

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    # Graceful degradation — works without colorama, just no colour.
    class _NoColor:
        def __getattr__(self, _: str) -> str:
            return ""

    Fore = Style = _NoColor()  # type: ignore[assignment]
    HAS_COLOR = False

import services as svc

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    port: int
    state: str  # "open", "closed", "filtered"
    service: str = ""
    banner: str = ""
    description: str = ""


@dataclass
class HostResult:
    host: str
    ip: str = ""
    os_hint: str = ""
    ttl: int = 0
    scan_time: float = 0.0
    ports: list[PortResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------

def resolve_targets(target_str: str) -> list[str]:
    """Expand a target specification into a list of IP address strings.

    Supports:
      - Single IP or hostname: ``192.168.1.1``, ``example.com``
      - CIDR notation: ``10.0.0.0/24``
      - Comma-separated list: ``192.168.1.1,192.168.1.2``
    """
    targets: list[str] = []
    for part in target_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            try:
                network = ipaddress.ip_network(part, strict=False)
                targets.extend(str(ip) for ip in network.hosts())
            except ValueError:
                _die(f"Invalid CIDR notation: {part}")
        else:
            # Could be a hostname — resolve once.
            try:
                ip = socket.gethostbyname(part)
                targets.append(ip)
            except socket.gaierror:
                _die(f"Cannot resolve host: {part}")
    return targets


def parse_ports(port_str: str) -> list[int]:
    """Parse a port specification such as ``22``, ``1-1024``, or ``22,80,443``."""
    ports: list[int] = []
    for segment in port_str.split(","):
        segment = segment.strip()
        if "-" in segment:
            try:
                lo, hi = segment.split("-", 1)
                lo_i, hi_i = int(lo), int(hi)
            except ValueError:
                _die(f"Invalid port range: {segment}")
            if lo_i < 1 or hi_i > 65535 or lo_i > hi_i:
                _die(f"Port range out of bounds: {segment}")
            ports.extend(range(lo_i, hi_i + 1))
        else:
            try:
                p = int(segment)
            except ValueError:
                _die(f"Invalid port number: {segment}")
            if p < 1 or p > 65535:
                _die(f"Port out of range: {p}")
            ports.append(p)
    return sorted(set(ports))


# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------

class ProgressBar:
    """Simple terminal progress bar that overwrites the current line."""

    def __init__(self, total: int, width: int = 40) -> None:
        self.total = total
        self.width = width
        self.done = 0
        self._lock = asyncio.Lock()

    async def advance(self, n: int = 1) -> None:
        async with self._lock:
            self.done = min(self.done + n, self.total)
            self._draw()

    def _draw(self) -> None:
        pct = self.done / self.total if self.total else 1
        filled = int(self.width * pct)
        bar = "█" * filled + "░" * (self.width - filled)
        sys.stderr.write(
            f"\r{Fore.CYAN}[{bar}] {self.done}/{self.total} "
            f"({pct:.0%}){Style.RESET_ALL}"
        )
        sys.stderr.flush()

    def finish(self) -> None:
        self.done = self.total
        self._draw()
        sys.stderr.write("\n")
        sys.stderr.flush()


# ---------------------------------------------------------------------------
# Banner grabbing
# ---------------------------------------------------------------------------

async def grab_banner(ip: str, port: int, timeout: float) -> str:
    """Attempt to read a service banner from an open port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        # Some services send a banner on connect; others need a nudge.
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        except asyncio.TimeoutError:
            # Try sending a generic probe.
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            except asyncio.TimeoutError:
                data = b""
        writer.close()
        await writer.wait_closed()
        banner = data.decode(errors="replace").strip()
        # Keep only the first line for tidiness.
        return banner.split("\n")[0][:256] if banner else ""
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# TCP connect scan
# ---------------------------------------------------------------------------

async def tcp_connect_scan(
    ip: str, port: int, timeout: float, banner: bool = True
) -> PortResult:
    """Perform a TCP connect() scan on a single port."""
    svc_name, desc = svc.lookup(port)
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        b = ""
        if banner:
            b = await grab_banner(ip, port, timeout)
        return PortResult(
            port=port, state="open", service=svc_name, banner=b, description=desc
        )
    except (asyncio.TimeoutError, ConnectionRefusedError):
        return PortResult(port=port, state="closed", service=svc_name, description=desc)
    except OSError:
        return PortResult(port=port, state="filtered", service=svc_name, description=desc)


# ---------------------------------------------------------------------------
# SYN scan (requires root / raw sockets)
# ---------------------------------------------------------------------------

def _build_syn_packet(src_ip: str, dst_ip: str, dst_port: int) -> bytes:
    """Build a raw TCP SYN packet with a pseudo-header checksum."""
    src_port = 44000 + (dst_port % 1000)

    # TCP header fields
    seq = 0
    ack_seq = 0
    offset_res = (5 << 4)
    tcp_flags = 0x02  # SYN
    window = socket.htons(5840)
    check = 0
    urg_ptr = 0

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack_seq,
        offset_res, tcp_flags, window, check, urg_ptr,
    )

    # Pseudo header for checksum
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)

    psh = struct.pack("!4s4sBBH", src_addr, dst_addr, placeholder, protocol, tcp_length)
    psh += tcp_header

    # Compute checksum
    chk = _checksum(psh)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack_seq,
        offset_res, tcp_flags, window, chk, urg_ptr,
    )
    return tcp_header


def _checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data) - 1, 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    if len(data) % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _get_local_ip() -> str:
    """Determine the local IP address used for outbound connections."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


async def syn_scan_port(
    ip: str, port: int, timeout: float
) -> PortResult:
    """Send a SYN packet and classify the response.  Requires root."""
    svc_name, desc = svc.lookup(port)
    try:
        src_ip = _get_local_ip()
        pkt = _build_syn_packet(src_ip, ip, port)

        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)
        send_sock.sendto(pkt, (ip, port))
        send_sock.close()

        # Listen for the response
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock.settimeout(timeout)

        start = time.monotonic()
        while time.monotonic() - start < timeout:
            try:
                data, addr = recv_sock.recvfrom(1024)
            except socket.timeout:
                recv_sock.close()
                return PortResult(port=port, state="filtered", service=svc_name, description=desc)

            if addr[0] == ip:
                # IP header is typically 20 bytes; TCP header starts after.
                ip_header_len = (data[0] & 0x0F) * 4
                tcp_header = data[ip_header_len:]
                src_port_resp = struct.unpack("!H", tcp_header[0:2])[0]
                flags = tcp_header[13]

                if src_port_resp == port:
                    recv_sock.close()
                    if flags & 0x12 == 0x12:  # SYN+ACK
                        return PortResult(port=port, state="open", service=svc_name, description=desc)
                    elif flags & 0x04:  # RST
                        return PortResult(port=port, state="closed", service=svc_name, description=desc)
                    break

        recv_sock.close()
        return PortResult(port=port, state="filtered", service=svc_name, description=desc)
    except PermissionError:
        _die("SYN scan requires root privileges. Run with sudo.")
        return PortResult(port=port, state="error")  # unreachable
    except Exception as exc:
        return PortResult(port=port, state="filtered", service=svc_name, description=desc)


# ---------------------------------------------------------------------------
# OS fingerprint heuristics
# ---------------------------------------------------------------------------

def guess_os(open_ports: list[int], ttl: int) -> str:
    """Return a rough OS guess based on open ports and TTL value."""
    hints: list[str] = []

    port_set = set(open_ports)

    # TTL-based hints
    if ttl:
        if ttl <= 64:
            hints.append("Linux/Unix (TTL<=64)")
        elif ttl <= 128:
            hints.append("Windows (TTL<=128)")
        elif ttl <= 255:
            hints.append("Solaris/AIX (TTL<=255)")

    # Port-based hints
    if port_set & {135, 139, 445, 3389}:
        hints.append("Windows (SMB/RDP ports)")
    if port_set & {22} and not port_set & {135, 445}:
        hints.append("Linux/Unix (SSH, no SMB)")
    if port_set & {548}:
        hints.append("macOS (AFP)")
    if port_set & {631}:
        hints.append("Linux (CUPS)")
    if port_set & {10000}:
        hints.append("Linux (Webmin)")

    return " | ".join(hints) if hints else "Unknown"


def measure_ttl(ip: str) -> int:
    """Attempt to measure TTL from a quick TCP or ICMP probe."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 80))
        ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        s.close()
        return ttl
    except Exception:
        pass
    # Fallback: try common open ports.
    for port in (443, 22, 21):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, port))
            ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            s.close()
            return ttl
        except Exception:
            continue
    return 0


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

async def scan_host(
    ip: str,
    ports: list[int],
    timeout: float,
    concurrency: int,
    syn: bool = False,
    progress: ProgressBar | None = None,
) -> HostResult:
    """Scan all specified ports on a single host."""
    result = HostResult(host=ip, ip=ip)
    semaphore = asyncio.Semaphore(concurrency)
    start = time.monotonic()

    async def _scan_one(port: int) -> PortResult:
        async with semaphore:
            if syn:
                r = await syn_scan_port(ip, port, timeout)
            else:
                r = await tcp_connect_scan(ip, port, timeout)
            if progress:
                await progress.advance()
            return r

    tasks = [asyncio.create_task(_scan_one(p)) for p in ports]
    results = await asyncio.gather(*tasks)
    result.ports = [r for r in results if r.state == "open"]
    result.scan_time = round(time.monotonic() - start, 2)

    # OS fingerprint
    open_ports = [r.port for r in result.ports]
    ttl = measure_ttl(ip)
    result.ttl = ttl
    result.os_hint = guess_os(open_ports, ttl)

    return result


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _format_table(results: list[HostResult], file: TextIO = sys.stdout) -> None:
    """Print a colour-coded table to the terminal."""
    separator = f"{Fore.WHITE}{'─' * 78}{Style.RESET_ALL}"

    for hr in results:
        file.write(f"\n{Fore.GREEN}{'=' * 78}{Style.RESET_ALL}\n")
        file.write(
            f"{Fore.GREEN}Scan Report: {Fore.WHITE}{hr.host}"
            f"{Style.RESET_ALL}\n"
        )
        file.write(separator + "\n")
        file.write(
            f"  {Fore.YELLOW}OS Hint  :{Style.RESET_ALL} {hr.os_hint}\n"
        )
        file.write(
            f"  {Fore.YELLOW}TTL      :{Style.RESET_ALL} {hr.ttl}\n"
        )
        file.write(
            f"  {Fore.YELLOW}Scan Time:{Style.RESET_ALL} {hr.scan_time}s\n"
        )
        file.write(separator + "\n")

        if not hr.ports:
            file.write(f"  {Fore.RED}No open ports found.{Style.RESET_ALL}\n")
            continue

        header = (
            f"  {Fore.CYAN}{'PORT':<10}{'STATE':<10}{'SERVICE':<18}"
            f"{'BANNER / INFO'}{Style.RESET_ALL}"
        )
        file.write(header + "\n")
        file.write(separator + "\n")

        for pr in sorted(hr.ports, key=lambda p: p.port):
            state_color = Fore.GREEN if pr.state == "open" else Fore.RED
            info = pr.banner if pr.banner else pr.description
            file.write(
                f"  {Fore.WHITE}{pr.port:<10}"
                f"{state_color}{pr.state:<10}"
                f"{Fore.MAGENTA}{pr.service:<18}"
                f"{Fore.WHITE}{info}{Style.RESET_ALL}\n"
            )

        file.write(f"{Fore.GREEN}{'=' * 78}{Style.RESET_ALL}\n")


def _format_json(results: list[HostResult], file: TextIO = sys.stdout) -> None:
    """Emit results as a JSON document."""
    data = []
    for hr in results:
        data.append(
            {
                "host": hr.host,
                "ip": hr.ip,
                "os_hint": hr.os_hint,
                "ttl": hr.ttl,
                "scan_time": hr.scan_time,
                "open_ports": [
                    {
                        "port": pr.port,
                        "state": pr.state,
                        "service": pr.service,
                        "banner": pr.banner,
                        "description": pr.description,
                    }
                    for pr in sorted(hr.ports, key=lambda p: p.port)
                ],
            }
        )
    json.dump(data, file, indent=2)
    file.write("\n")


def _format_csv(results: list[HostResult], file: TextIO = sys.stdout) -> None:
    """Emit results as CSV rows."""
    writer = csv.writer(file)
    writer.writerow(["host", "port", "state", "service", "banner", "description", "os_hint"])
    for hr in results:
        for pr in sorted(hr.ports, key=lambda p: p.port):
            writer.writerow(
                [hr.host, pr.port, pr.state, pr.service, pr.banner, pr.description, hr.os_hint]
            )


FORMATTERS = {
    "table": _format_table,
    "json": _format_json,
    "csv": _format_csv,
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Advanced async TCP port scanner with service detection.",
        epilog="Example: python3 scanner.py --target 192.168.1.1 --ports 1-1024 --threads 200",
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target host, CIDR range, or comma-separated list of hosts.",
    )
    ports_group = parser.add_mutually_exclusive_group()
    ports_group.add_argument(
        "--ports", "-p",
        default=None,
        help="Port specification: single (80), range (1-1024), or list (22,80,443).",
    )
    ports_group.add_argument(
        "--top-ports",
        type=int,
        default=None,
        metavar="N",
        help="Scan the top N most common ports (max %d)." % len(svc.TOP_PORTS),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=200,
        help="Maximum concurrent connections (default: 200).",
    )
    parser.add_argument(
        "--format", "-f",
        choices=FORMATTERS.keys(),
        default="table",
        help="Output format (default: table).",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        metavar="FILE",
        help="Write output to FILE instead of stdout.",
    )
    parser.add_argument(
        "--syn",
        action="store_true",
        help="Use SYN (half-open) scan — requires root privileges.",
    )
    return parser


def _die(msg: str) -> None:
    sys.stderr.write(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}\n")
    sys.exit(1)


def _banner() -> None:
    art = rf"""
{Fore.CYAN}    ___       __                               __   ____                  __  ___
   /   | ____/ /   ______ _____  ________  ____/ /  / __ \____  _____/ /_/ ___/_________ _____  ____  ___  _____
  / /| |/ __  / | / / __ `/ __ \/ ___/ _ \/ __  /  / /_/ / __ \/ ___/ __/\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / ___ / /_/ /| |/ / /_/ / / / / /__/  __/ /_/ /  / ____/ /_/ / /  / /_ ___/ / /__/ /_/ / / / / / / /  __/ /
/_/  |_\__,_/ |___/\__,_/_/ /_/\___/\___/\__,_/  /_/    \____/_/   \__//____/\___/\__,_/_/ /_/_/ /_/\___/_/
{Style.RESET_ALL}
{Fore.WHITE}  Advanced Async Port Scanner — Service Detection & Banner Grabbing{Style.RESET_ALL}
"""
    sys.stderr.write(art + "\n")


async def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    _banner()

    # Resolve targets.
    targets = resolve_targets(args.target)
    if not targets:
        _die("No valid targets specified.")

    # Determine ports.
    if args.ports:
        ports = parse_ports(args.ports)
    elif args.top_ports:
        ports = svc.top_n_ports(args.top_ports)
    else:
        # Default: top 100 ports.
        ports = svc.top_n_ports(100)

    if not ports:
        _die("No valid ports specified.")

    total_probes = len(targets) * len(ports)
    scan_type = "SYN" if args.syn else "TCP Connect"

    sys.stderr.write(
        f"{Fore.YELLOW}[*]{Style.RESET_ALL} Scan type    : {scan_type}\n"
        f"{Fore.YELLOW}[*]{Style.RESET_ALL} Targets      : {len(targets)}\n"
        f"{Fore.YELLOW}[*]{Style.RESET_ALL} Ports/host   : {len(ports)}\n"
        f"{Fore.YELLOW}[*]{Style.RESET_ALL} Total probes : {total_probes}\n"
        f"{Fore.YELLOW}[*]{Style.RESET_ALL} Concurrency  : {args.threads}\n"
        f"{Fore.YELLOW}[*]{Style.RESET_ALL} Timeout      : {args.timeout}s\n\n"
    )

    if args.syn and os.geteuid() != 0:
        _die("SYN scan requires root privileges. Re-run with sudo.")

    progress = ProgressBar(total_probes)
    all_results: list[HostResult] = []

    for ip in targets:
        hr = await scan_host(
            ip,
            ports,
            timeout=args.timeout,
            concurrency=args.threads,
            syn=args.syn,
            progress=progress,
        )
        all_results.append(hr)

    progress.finish()
    sys.stderr.write("\n")

    # Output
    formatter = FORMATTERS[args.format]
    if args.output:
        with open(args.output, "w") as fh:
            formatter(all_results, fh)
        sys.stderr.write(
            f"{Fore.GREEN}[+]{Style.RESET_ALL} Results written to {args.output}\n"
        )
    else:
        formatter(all_results)

    # Summary
    total_open = sum(len(hr.ports) for hr in all_results)
    sys.stderr.write(
        f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Scan complete: "
        f"{total_open} open port(s) found across {len(all_results)} host(s).\n"
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.stderr.write(f"\n{Fore.RED}[!] Scan interrupted by user.{Style.RESET_ALL}\n")
        sys.exit(130)
