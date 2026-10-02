"""No expansion, command splitting, filesystem lookup or target codec discovery."""

import uuid

from .contracts import BudgetStop, ParseFailure


def indicators(value):
    result = []
    if value.startswith("\\\\") or value.startswith("//"):
        result.append("unc_like")
    if "://" in value:
        result.append("url_like")
    if "%" in value:
        result.append("environment_marker")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        result.append("control_character")
    if any(ord(c) in range(0x202A, 0x202F) or ord(c) in range(0x2066, 0x206A) for c in value):
        result.append("bidi_control")
    if ".." in value.replace("\\", "/").split("/"):
        result.append("parent_path_segment")
    if any(c in value for c in "&|<>`"):
        result.append("shell_metacharacter")
    return result


def decode(ctx, span, encoding, kind, terminated=False, fixed=False):
    if len(span) > ctx.limits.text_field_bytes:
        raise BudgetStop("text_field_bytes_budget", span.start)
    ctx.charge("text_bytes", len(span), span.start)
    raw = span.read(0, len(span))
    unit = 2 if encoding == "utf-16-le" else 1
    end = len(raw)
    terminated_at = None
    if terminated:
        for index in range(0, len(raw) - unit + 1, unit):
            if raw[index : index + unit] == b"\0" * unit:
                end = index
                terminated_at = index
                break
        if terminated_at is None:
            raise ParseFailure("missing_string_terminator", span.start)
        if not fixed and end + unit != len(raw):
            ctx.issue("OPEN", "string_tail_uninterpreted", span.start + end + unit)
    content = raw[:end]
    actual_encoding = encoding
    if encoding == "ansi":
        actual_encoding = ctx.ansi_codepage or "ascii"
    status = "PASS"
    value = None
    try:
        value = content.decode(actual_encoding, errors="strict")
    except UnicodeError:
        status = "OPEN" if encoding == "ansi" else "FAIL"
        ctx.issue(
            status,
            "unresolved_ansi_encoding" if encoding == "ansi" else "invalid_unicode",
            span.start,
        )
    if value is not None and not terminated and "\0" in value:
        status = "OPEN"
        ctx.issue("OPEN", "counted_string_contains_nul", span.start)
    rec = ctx.record(
        kind,
        span,
        encoding=actual_encoding,
        encoding_assertion="caller"
        if encoding == "ansi" and ctx.ansi_codepage
        else "format_or_ascii_subset",
        decode_status=status,
        content_bytes=end,
        nul_offset=None if terminated_at is None else span.start + terminated_at,
        indicators=[] if value is None else indicators(value),
        text_redacted=not ctx.show_text,
    )
    if ctx.show_text and value is not None:
        rec["text"] = value
    return value, rec


def cstring(ctx, owner, offset, encoding, kind, minimum=0):
    if offset < minimum or offset >= len(owner):
        raise ParseFailure("string_offset_out_of_bounds", owner.start + max(0, offset))
    unit = 2 if encoding == "utf-16-le" else 1
    available = len(owner) - offset
    bound = min(available, ctx.limits.text_field_bytes)
    end = None
    for index in range(0, bound - unit + 1, unit):
        if owner.read(offset + index, unit) == b"\0" * unit:
            end = index + unit
            break
    if end is None:
        if available > bound:
            raise BudgetStop("text_field_bytes_budget", owner.start + offset)
        raise ParseFailure("missing_string_terminator", owner.start + offset)
    return decode(ctx, owner.sub(offset, end), encoding, kind, terminated=True)


def guid(ctx, owner, offset, kind):
    span = owner.sub(offset, 16)
    value = str(uuid.UUID(bytes_le=span.read(0, 16)))
    rec = ctx.record(kind, span, text_redacted=not ctx.show_text)
    if ctx.show_text:
        rec["guid"] = value
    return value
