"""Pure immutable-byte review; PASS certifies this finite format profile only."""

import hashlib
import json

from .binary import Context, Span
from .contracts import ASSUMPTIONS, BudgetStop, Limits, ParseFailure, limits_dict
from .extra import parse_extras
from .header import parse_header
from .idlist import parse_idlist
from .linkinfo import parse_linkinfo
from .text import decode


def encode_report(report):
    return json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n"


def open_report(code, limits=None):
    selected = Limits() if limits is None else limits
    return {
        "schema": "lnk-evidence-review/v1",
        "status": "OPEN",
        "complete": False,
        "input": {"admitted": False, "sha256": None},
        "records": [],
        "findings": [{"status": "OPEN", "code": code, "offset": None}],
        "limits": limits_dict(selected),
        "assumptions": dict(ASSUMPTIONS),
    }


def review_bytes(data, *, limits=None, show_text=False, ansi_codepage=None):
    if type(data) is not bytes:
        raise TypeError("immutable_bytes_required")
    selected = Limits() if limits is None else limits
    if type(selected) is not Limits:
        raise TypeError("limits_required")
    if type(show_text) is not bool:
        raise TypeError("boolean_show_text_required")
    if ansi_codepage not in (None, "cp1252", "cp437"):
        raise ValueError("unsupported_ansi_codepage")
    if len(data) > selected.input_bytes:
        result = open_report("input_bytes_budget", selected)
        result["input"]["size"] = len(data)
        return result
    ctx = Context(selected, show_text, ansi_codepage)
    owner = Span(data)
    try:
        flags = parse_header(ctx, owner)
        position, target_boundaries = 76, None
        if flags & 1:
            size = owner.u16(position)
            ctx.record("target_idlist_size", owner.sub(position, 2), declared_size=size)
            target_boundaries = parse_idlist(ctx, owner.sub(position + 2, size))
            position += 2 + size
        if flags & 2:
            size = owner.u32(position)
            parse_linkinfo(ctx, owner.sub(position, size), bool(flags & 0x100))
            position += size
        for bit, kind in (
            (4, "name"),
            (8, "relative_path"),
            (16, "working_directory"),
            (32, "arguments"),
            (64, "icon_location"),
        ):
            if flags & bit:
                count = owner.u16(position)
                size = count * (2 if flags & 0x80 else 1)
                if kind != "arguments" and count > 260:
                    ctx.issue(
                        "FAIL", "non_argument_string_exceeds_max_path", owner.start + position
                    )
                field = owner.sub(position + 2, size)
                _, record = decode(
                    ctx, field, "utf-16-le" if flags & 0x80 else "ansi", "string_" + kind
                )
                record["declared_character_count"] = count
                record["count_field_offset"] = owner.start + position
                position += 2 + size
        signatures = parse_extras(ctx, owner, position, target_boundaries)
        for bit, signature in (
            (0x200, 0xA0000001),
            (0x1000, 0xA0000006),
            (0x4000, 0xA0000007),
            (0x20000, 0xA0000008),
        ):
            if flags & bit and signature not in signatures:
                ctx.issue("FAIL", "flag_requires_missing_extra_block", 20)
            elif signature in signatures and not flags & bit:
                ctx.issue("OPEN", "extra_block_without_corresponding_flag", 20)
    except ParseFailure as error:
        ctx.issue("FAIL", error.code, error.offset)
    except BudgetStop as error:
        ctx.issue("OPEN", error.code, error.offset)
    result = {
        "schema": "lnk-evidence-review/v1",
        "status": "FAIL" if ctx.fail else "OPEN" if ctx.open else "PASS",
        "complete": not ctx.fail and not ctx.open,
        "input": {"admitted": True, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()},
        "records": ctx.records,
        "findings": ctx.findings,
        "finding_budget_exceeded": len(ctx.seen_findings) > selected.findings,
        "counts": ctx.counts,
        "limits": limits_dict(selected),
        "text_disclosure": "explicit_caller_opt_in" if show_text else "redacted",
        "ansi_codepage_assertion": ansi_codepage,
        "assumptions": dict(ASSUMPTIONS),
    }
    if len(encode_report(result).encode("ascii")) > selected.report_bytes:
        ctx.issue("OPEN", "report_bytes_budget", 0)
        result["status"] = "FAIL" if ctx.fail else "OPEN"
        result["complete"] = False
        result["records"] = []
        result["findings"] = [{"status": "OPEN", "code": "report_bytes_budget", "offset": 0}]
        if ctx.fail:
            result["findings"].append(
                {"status": "FAIL", "code": "known_format_failure_retained", "offset": None}
            )
        result["finding_budget_exceeded"] = True
    return result
