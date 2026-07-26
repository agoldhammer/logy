"""Tests for the nginx log analyzer."""

from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import main


class PageFromRequestTests(unittest.TestCase):
    def test_extracts_path_from_valid_request(self) -> None:
        self.assertEqual(main.page_from_request("GET /posts?q=1 HTTP/1.1"), "/posts?q=1")

    def test_marks_empty_and_malformed_requests(self) -> None:
        self.assertEqual(main.page_from_request(""), "<empty request>")
        self.assertEqual(
            main.page_from_request("not an HTTP request"),
            "<malformed: not an HTTP request>",
        )

    def test_truncates_an_overlong_malformed_request(self) -> None:
        page = main.page_from_request("x" * (main.MAX_REQUEST_CHARS + 10))
        self.assertEqual(page, f"<malformed: {'x' * main.MAX_REQUEST_CHARS}...>")

    def test_keeps_a_malformed_request_at_the_length_limit_intact(self) -> None:
        request = "y" * main.MAX_REQUEST_CHARS
        self.assertEqual(main.page_from_request(request), f"<malformed: {request}>")


class AnalyzeTests(unittest.TestCase):
    def analyze_text(self, text: str):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "access.log"
            log.write_text(text)
            return main.analyze(log)

    def test_classifies_accesses_and_records_every_page_hit(self) -> None:
        granted, denied, unparsed = self.analyze_text(
            '192.0.2.1 - - [01/Jan/2025:10:00:00 +0000] "GET /old HTTP/1.1" 200 10\n'
            '192.0.2.1 - - [02/Jan/2025:10:00:00 +0000] "GET /old HTTP/1.1" 200 10\n'
            '2001:db8::1 - - [01/Jan/2025:11:00:00 +0000] "POST /private HTTP/1.1" 403 10\n'
            '192.0.2.2 - - [01/Jan/2025:12:00:00 +0000] "GET /redirect HTTP/1.1" 301 10\n'
        )

        self.assertEqual(unparsed, 0)
        self.assertEqual(set(granted), {"192.0.2.1"})
        self.assertEqual(set(denied), {"2001:db8::1"})
        self.assertEqual(
            granted["192.0.2.1"]["/old"],
            [
                datetime.strptime("01/Jan/2025:10:00:00 +0000", main.TIME_FORMAT),
                datetime.strptime("02/Jan/2025:10:00:00 +0000", main.TIME_FORMAT),
            ],
        )
        self.assertIn("/private", denied["2001:db8::1"])

    def test_counts_nonempty_invalid_lines_and_invalid_timestamps(self) -> None:
        granted, denied, unparsed = self.analyze_text(
            "not an nginx line\n\n"
            '192.0.2.1 - - [not-a-date] "GET / HTTP/1.1" 200 10\n'
        )

        self.assertEqual((dict(granted), dict(denied), unparsed), ({}, {}, 2))

    def test_records_malformed_request_as_a_page(self) -> None:
        granted, _, _ = self.analyze_text(
            '192.0.2.1 - - [01/Jan/2025:10:00:00 +0000] "BROKEN" 200 10\n'
        )
        self.assertIn("<malformed: BROKEN>", granted["192.0.2.1"])


class HelperTests(unittest.TestCase):
    def test_reverse_dns_returns_fallback_for_lookup_error(self) -> None:
        with patch("main.socket.gethostbyaddr", side_effect=OSError):
            self.assertEqual(
                main.reverse_dns(["192.0.2.1"]),
                {"192.0.2.1": "no reverse DNS"},
            )

    def test_host_in_ssh_config_matches_named_host_but_not_catch_all(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            ssh = home / ".ssh"
            ssh.mkdir()
            (ssh / "config").write_text("Host *\nHost web-? !web-bad\n")
            with patch("main.Path.home", return_value=home):
                self.assertTrue(main.host_in_ssh_config("web-1"))
                self.assertFalse(main.host_in_ssh_config("anything"))

    def test_fetch_remote_log_removes_failed_download(self) -> None:
        result = MagicMock(returncode=1)
        with patch("main.subprocess.run", return_value=result), patch(
            "main.tempfile.NamedTemporaryFile"
        ) as temporary:
            temp = tempfile.NamedTemporaryFile(delete=False)
            temp.close()
            temporary.return_value = SimpleNamespace(name=temp.name, close=MagicMock())
            try:
                with self.assertRaisesRegex(SystemExit, "scp failed"):
                    main.fetch_remote_log("server")
                self.assertFalse(Path(temp.name).exists())
            finally:
                Path(temp.name).unlink(missing_ok=True)

    def test_bot_and_ip_sort_helpers(self) -> None:
        self.assertTrue(main.is_bot_page("/.well-known/acme-challenge/x"))
        self.assertFalse(main.is_bot_page("/articles"))
        self.assertLess(main.ip_sort_key("10.0.0.1"), main.ip_sort_key("not-an-ip"))

    def test_latest_access_spans_all_pages_and_hits(self) -> None:
        pages = {
            "/a": [datetime(2025, 1, 1), datetime(2025, 1, 4)],
            "/b": [datetime(2025, 1, 3)],
        }
        self.assertEqual(main.latest_access(pages), datetime(2025, 1, 4))


class PrintAndCliTests(unittest.TestCase):
    def test_print_section_sorts_ips_and_uses_singular_page_label(self) -> None:
        zone = datetime.now().astimezone().tzinfo
        table = {
            "10.0.0.2": {"/b": [datetime(2025, 1, 2, tzinfo=zone)]},
            "10.0.0.1": {"/a": [datetime(2025, 1, 1, tzinfo=zone)]},
        }
        output = io.StringIO()
        with redirect_stdout(output):
            main.print_section(
                "Test",
                table,
                {"10.0.0.1": "one", "10.0.0.2": "two"},
                color=False,
            )

        text = output.getvalue()
        self.assertLess(text.index("10.0.0.1"), text.index("10.0.0.2"))
        self.assertIn("10.0.0.1 [one]  (1 page, 1 access)", text)
        self.assertNotIn("\033[", text)

    def test_print_section_singularizes_a_lone_ip_in_the_title(self) -> None:
        table = {"10.0.0.1": {"/a": [datetime.now().astimezone()]}}
        output = io.StringIO()
        with redirect_stdout(output):
            main.print_section("Test", table, color=False)
        self.assertIn("=== Test — 1 distinct IP ===", output.getvalue())

    def test_print_section_lists_every_access_to_a_repeated_page(self) -> None:
        zone = datetime.now().astimezone().tzinfo
        table = {
            "10.0.0.1": {
                "/a": [
                    datetime(2025, 1, 3, tzinfo=zone),
                    datetime(2025, 1, 1, tzinfo=zone),
                ],
                "/b": [datetime(2025, 1, 2, tzinfo=zone)],
            }
        }
        output = io.StringIO()
        with redirect_stdout(output):
            main.print_section("Test", table, color=False)

        self.assertIn("10.0.0.1  (2 pages, 3 accesses)", output.getvalue())
        lines = [line for line in output.getvalue().splitlines() if line.startswith("    ")]
        self.assertEqual(
            [line.split("] ")[1] for line in lines], ["/a", "/a", "/b"]
        )
        self.assertIn("01/Jan", lines[0])
        self.assertIn("03/Jan", lines[1])

    def test_parse_args_reads_flags_and_logfile(self) -> None:
        with patch.object(sys, "argv", ["main.py", "--no-denied", "--time-sort", "example.log"]):
            args = main.parse_args()
        self.assertTrue(args.no_denied)
        self.assertTrue(args.time_sort)
        self.assertEqual(args.logfile, Path("example.log"))

    def test_main_filters_bot_only_ips_and_honors_no_denied(self) -> None:
        granted = {
            "192.0.2.1": {"/": [datetime.now().astimezone()]},
            "192.0.2.2": {"/real": [datetime.now().astimezone()]},
        }
        denied = {"192.0.2.3": {"/private": [datetime.now().astimezone()]}}
        args = MagicMock(
            remote=None,
            logfile=Path("example.log"),
            no_bots=True,
            no_color=True,
            no_denied=True,
            time_sort=False,
        )
        output = io.StringIO()
        with patch("main.parse_args", return_value=args), patch.object(
            Path, "is_file", return_value=True
        ), patch("main.analyze", return_value=(granted, denied, 0)), patch(
            "main.reverse_dns", return_value={"192.0.2.2": "visitor.example"}
        ), patch("main.progress_dots"):
            with redirect_stdout(output):
                main.main()

        text = output.getvalue()
        self.assertIn("192.0.2.2", text)
        self.assertNotIn("192.0.2.1", text)
        self.assertNotIn("IPs denied", text)


if __name__ == "__main__":
    unittest.main()
