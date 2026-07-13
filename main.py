"""Analyze an nginx access log (combined format).

Reports distinct IP addresses that received a 200 response, with the pages
each accessed, and distinct IP addresses that were denied access (any 4xx
status), with the pages each attempted. Every line is prefixed with the
timestamp of the relevant access (the most recent one, if a page was hit
more than once). Displayed allowed IPs are annotated with their reverse-DNS
hostname.

Usage: uv run main.py [--no-denied] [--no-bots] [--time-sort] [--no-color] [logfile]
"""

import argparse
import fnmatch
import ipaddress
import re
import socket
import subprocess
import tempfile
import threading
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REMOTE_LOG = "/var/log/nginx/access.log"

LOG_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) \S+'
)

REQUEST = re.compile(r"^[A-Z]+ (?P<page>\S+) HTTP/[\d.]+$")

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# page -> time of the most recent access, keyed by IP
AccessTable = dict[str, dict[str, datetime]]


def page_from_request(request: str) -> str:
    """Extract the requested path; fall back to the raw request if malformed."""
    match = REQUEST.match(request)
    if match:
        return match.group("page")
    return f"<malformed: {request}>" if request else "<empty request>"


def analyze(log_path: Path) -> tuple[AccessTable, AccessTable, int]:
    granted: AccessTable = defaultdict(dict)
    denied: AccessTable = defaultdict(dict)
    unparsed = 0

    with log_path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            match = LOG_LINE.match(line)
            if not match:
                if line.strip():
                    unparsed += 1
                continue
            try:
                when = datetime.strptime(match.group("time"), TIME_FORMAT)
            except ValueError:
                unparsed += 1
                continue
            ip = match.group("ip")
            status = int(match.group("status"))
            page = page_from_request(match.group("request"))
            if status == 200:
                table = granted
            elif 400 <= status <= 499:
                table = denied
            else:
                continue
            prev = table[ip].get(page)
            if prev is None or when > prev:
                table[ip][page] = when

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


def host_in_ssh_config(host: str) -> bool:
    """True if host matches a Host entry in ~/.ssh/config (catch-alls excluded)."""
    config = Path.home() / ".ssh" / "config"
    if not config.is_file():
        return False
    for line in config.read_text().splitlines():
        line = line.strip()
        if not line.lower().startswith("host ") and not line.lower().startswith("host\t"):
            continue
        for pattern in line.split()[1:]:
            if pattern.startswith("!") or set(pattern) <= {"*", "?"}:
                continue
            if fnmatch.fnmatch(host, pattern):
                return True
    return False


def fetch_remote_log(host: str) -> Path:
    """Copy the nginx access log from the remote host to a temp file via scp."""
    tmp = tempfile.NamedTemporaryFile(
        prefix=f"{host}-access-", suffix=".log", delete=False
    )
    tmp.close()
    result = subprocess.run(["scp", "-q", f"{host}:{REMOTE_LOG}", tmp.name])
    if result.returncode != 0:
        Path(tmp.name).unlink(missing_ok=True)
        raise SystemExit(f"error: scp failed to fetch {host}:{REMOTE_LOG}")
    return Path(tmp.name)


@contextmanager
def progress_dots(interval: float = 2.0):
    """Print a dot every `interval` seconds until the with-block exits."""
    stop = threading.Event()
    dotted = False

    def tick() -> None:
        nonlocal dotted
        while not stop.wait(interval):
            print(".", end="", flush=True)
            dotted = True

    thread = threading.Thread(target=tick, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join()
        if dotted:
            print(flush=True)


def is_bot_page(page: str) -> bool:
    """Pages whose access suggests an automated crawler rather than a visitor."""
    return page == "/" or page == "/robots.txt" or page.startswith("/.well-known/")


def ip_sort_key(ip: str):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


RED = "\033[31m"
RESET = "\033[0m"


def print_section(
    title: str,
    table: AccessTable,
    hostnames: dict[str, str] | None = None,
    color: bool = True,
    time_sort: bool = False,
) -> None:
    red, reset = (RED, RESET) if color else ("", "")
    print(f"=== {title} — {len(table)} distinct IPs ===")
    if time_sort:
        order = sorted(table, key=lambda ip: max(table[ip].values()))
    else:
        order = sorted(table, key=ip_sort_key)
    for ip in order:
        pages = table[ip]
        label = "page" if len(pages) == 1 else "pages"
        host = f" [{hostnames[ip]}]" if hostnames else ""
        latest = max(pages.values()).strftime(TIME_FORMAT)
        print(f"{red}[{latest}] {ip}{host}  ({len(pages)} {label}){reset}")
        for page in sorted(pages):
            print(f"    [{pages[page].strftime(TIME_FORMAT)}] {page}")
        print()


def parse_args() -> argparse.Namespace:
    default_log = Path(__file__).parent / "data" / "access.log"
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "logfile", nargs="?", type=Path, default=default_log,
        help=f"nginx access log to analyze (default: {default_log})",
    )
    parser.add_argument(
        "-d", "--no-denied", action="store_true",
        help="suppress the denied-access (4xx) section",
    )
    parser.add_argument(
        "-b", "--no-bots", action="store_true",
        help="suppress allowed IPs that only accessed /, /robots.txt, or /.well-known/*",
    )
    parser.add_argument(
        "-t", "--time-sort", action="store_true",
        help="order each section by the latest access time per IP "
        "(oldest first) instead of by IP address",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="disable colored output",
    )
    parser.add_argument(
        "-r", "--remote", metavar="HOST",
        help=f"fetch {REMOTE_LOG} via scp from a host defined in ~/.ssh/config "
        "(overrides logfile)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.remote:
        if not host_in_ssh_config(args.remote):
            raise SystemExit(
                f"error: host '{args.remote}' not found in ~/.ssh/config"
            )
        print(f"logy: analyzing remote log {args.remote}:{REMOTE_LOG}", flush=True)
        logfile = fetch_remote_log(args.remote)
    else:
        logfile = args.logfile
        print(f"logy: analyzing local log {logfile}", flush=True)
    if not logfile.is_file():
        raise SystemExit(f"error: log file not found: {logfile}")

    with progress_dots():
        granted, denied, unparsed = analyze(logfile)

        if args.no_bots:
            granted = {
                ip: pages
                for ip, pages in granted.items()
                if not all(is_bot_page(page) for page in pages)
            }

        hostnames = reverse_dns(list(granted))

    color = not args.no_color
    print_section(
        "IPs granted access (200)", granted, hostnames, color, args.time_sort
    )
    if not args.no_denied:
        print_section(
            "IPs denied access (4xx)", denied, color=color, time_sort=args.time_sort
        )
    if unparsed:
        print(f"note: {unparsed} line(s) could not be parsed and were skipped")


if __name__ == "__main__":
    main()
