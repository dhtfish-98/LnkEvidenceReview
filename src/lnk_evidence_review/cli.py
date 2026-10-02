"""One escaped JSON report and stable exit status; argument errors never echo paths."""

import argparse
import sys

from .contracts import Limits
from .files import InputOpen, read_snapshot
from .review import encode_report, open_report, review_bytes


class ArgumentsOpen(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ArgumentsOpen


def positive_ascii(value):
    if not value or any(c not in "0123456789" for c in value) or len(value) > 10:
        raise argparse.ArgumentTypeError("invalid_limit")
    return int(value)


def main(argv=None):
    selected = Limits()
    try:
        parser = Parser(
            prog="lnk-evidence-review",
            description="Offline bounded Shell Link metadata evidence review.",
            allow_abbrev=False,
        )
        parser.add_argument("input_file")
        parser.add_argument(
            "--show-text",
            action="store_true",
            help="Explicitly disclose escaped text, GUIDs and property scalars.",
        )
        parser.add_argument("--ansi-codepage", choices=("cp1252", "cp437"))
        parser.add_argument("--input-bytes", type=positive_ascii, default=selected.input_bytes)
        parser.add_argument("--report-bytes", type=positive_ascii, default=selected.report_bytes)
        args = parser.parse_args(argv)
        selected = Limits(input_bytes=args.input_bytes, report_bytes=args.report_bytes)
        data = read_snapshot(args.input_file, selected.input_bytes)
        report = review_bytes(
            data, limits=selected, show_text=args.show_text, ansi_codepage=args.ansi_codepage
        )
    except (ArgumentsOpen, ValueError, TypeError):
        report = open_report("invalid_arguments", selected)
    except InputOpen as error:
        report = open_report(error.code, selected)
    try:
        sys.stdout.write(encode_report(report))
    except BrokenPipeError:
        return 2
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]
