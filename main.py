"""Analyze an nginx access log (combined format).

Reports distinct IP addresses that received a 200 response, with the pages
each accessed, and distinct IP addresses that were denied access (any 4xx
status), with the pages each attempted. Displayed allowed IPs are annotated
with their reverse-DNS hostname.

Usage: uv run main.py [--no-denied] [--no-root-only] [logfile]
"""

import argparse
import ipaddress
import re
import socket
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

LOG_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) \S+'
)

REQUEST = re.compile(r"^[A-Z]+ (?P<page>\S+) HTTP/[\d.]+$")


def page_from_request(request: str) -> str:
    """Extract the requested path; fall back to the raw request if malformed."""
    match = REQUEST.match(request)
    if match:
        return match.group("page")
    return f"<malformed: {request}>" if request else "<empty request>"


def analyze(log_path: Path) -> tuple[dict[str, set[str]], dict[str, set[str]], int]:
    granted: dict[str, set[str]] = defaultdict(set)
    denied: dict[str, set[str]] = defaultdict(set)
    unparsed = 0

    with log_path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            match = LOG_LINE.match(line)
            if not match:
                if line.strip():
                    unparsed += 1
                continue
            ip = match.group("ip")
            status = int(match.group("status"))
            page = page_from_request(match.group("request"))
            if status == 200:
                granted[ip].add(page)
            elif 400 <= status <= 499:
                denied[ip].add(page)

    return granted, denied, unparsed


def reverse_dns(ips: list[str]) -> dict[str, str]:
    """Resolve hostnames for the given IPs concurrently."""

    def lookup(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return "no reverse DNS"

    with ThreadPoolExecutor(max_workers=min(32, len(ips) or 1)) as pool:
        return dict(zip(ips, pool.map(lookup, ips)))


def ip_sort_key(ip: str):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


RED = "\033[31m"
RESET = "\033[0m"


def print_section(
    title: str,
    table: dict[str, set[str]],
    hostnames: dict[str, str] | None = None,
    color: bool = True,
) -> None:
    red, reset = (RED, RESET) if color else ("", "")
    print(f"=== {title} — {len(table)} distinct IPs ===")
    for ip in sorted(table, key=ip_sort_key):
        pages = sorted(table[ip])
        label = "page" if len(pages) == 1 else "pages"
        host = f" [{hostnames[ip]}]" if hostnames else ""
        print(f"{red}{ip}{host}  ({len(pages)} {label}){reset}")
        for page in pages:
            print(f"    {page}")
        print()


def parse_args() -> argparse.Namespace:
    default_log = Path(__file__).parent / "data" / "access.log"
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "logfile", nargs="?", type=Path, default=default_log,
        help=f"nginx access log to analyze (default: {default_log})",
    )
    parser.add_argument(
        "--no-denied", action="store_true",
        help="suppress the denied-access (4xx) section",
    )
    parser.add_argument(
        "--no-root-only", action="store_true",
        help="suppress allowed IPs whose only accessed page is /",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="disable colored output",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.logfile.is_file():
        raise SystemExit(f"error: log file not found: {args.logfile}")

    granted, denied, unparsed = analyze(args.logfile)

    if args.no_root_only:
        granted = {ip: pages for ip, pages in granted.items() if pages != {"/"}}

    color = not args.no_color
    hostnames = reverse_dns(list(granted))
    print_section("IPs granted access (200)", granted, hostnames, color)
    if not args.no_denied:
        print_section("IPs denied access (4xx)", denied, color=color)
    if unparsed:
        print(f"note: {unparsed} line(s) could not be parsed and were skipped")


if __name__ == "__main__":
    main()
