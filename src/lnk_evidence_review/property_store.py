"""Bounded MS-PROPSTORE framing and a frozen MS-OLEPS scalar value subset."""

import math
import uuid

from .contracts import ParseFailure
from .text import decode, guid


STRING_NAMES = "d5cdd505-2e9c-101b-9397-08002b2cf9ae"
SCALARS = {
    2: ("h", 4),
    3: ("i", 4),
    4: ("f", 4),
    5: ("d", 8),
    10: ("I", 4),
    11: ("h", 4),
    16: ("b", 4),
    17: ("B", 4),
    18: ("H", 4),
    19: ("I", 4),
    20: ("q", 8),
    21: ("Q", 8),
    22: ("i", 4),
    23: ("I", 4),
    64: ("Q", 8),
}


def typed(ctx, owner):
    typ = owner.u16(0)
    if owner.u16(2):
        ctx.issue("FAIL", "typed_property_nonzero_padding", owner.start + 2)
    body = owner.sub(4, len(owner) - 4)
    rec = ctx.record("typed_property", owner, variant_type=typ, value_redacted=not ctx.show_text)
    if typ in (0, 1):
        if len(body):
            ctx.issue("FAIL", "empty_property_has_payload", body.start)
    elif typ in SCALARS:
        fmt, size = SCALARS[typ]
        if len(body) != size:
            raise ParseFailure("invalid_scalar_property_size", body.start)
        value = body.num(0, fmt)
        consumed = {"h": 2, "b": 1, "B": 1, "H": 2}.get(fmt, size)
        if any(body.read(consumed, size - consumed)):
            ctx.issue("FAIL", "scalar_property_nonzero_padding", body.start + consumed)
        if typ == 11 and value not in (0, -1):
            ctx.issue("FAIL", "invalid_variant_bool", body.start)
        if isinstance(value, float) and not math.isfinite(value):
            ctx.issue("OPEN", "nonfinite_property_value", body.start)
        elif ctx.show_text:
            rec["value"] = value
    elif typ in (8, 30, 31, 65, 70):
        length = body.u32(0)
        byte_length = length * 2 if typ == 31 else length
        padded = (byte_length + 3) & ~3
        if len(body) != 4 + padded:
            raise ParseFailure("invalid_counted_property_size", body.start)
        content = body.sub(4, byte_length)
        if any(body.read(4 + byte_length, padded - byte_length)):
            ctx.issue("FAIL", "counted_property_nonzero_padding", body.start + 4 + byte_length)
        if typ in (65, 70):
            ctx.record("property_blob", content, interpretation="OPEN")
            ctx.issue("OPEN", "opaque_property_blob", content.start)
        elif byte_length:
            encoding = "utf-16-le" if typ == 31 else "ansi"
            unit = 2 if typ == 31 else 1
            if content.read(byte_length - unit, unit) != b"\0" * unit:
                raise ParseFailure("missing_property_string_terminator", content.end - unit)
            decode(ctx, content, encoding, "property_string", terminated=True)
            if typ != 31:
                ctx.issue("OPEN", "property_codepage_semantics_unresolved", content.start)
    elif typ == 72:
        if len(body) != 16:
            raise ParseFailure("invalid_guid_property_size", body.start)
        guid(ctx, body, 0, "property_guid")
    else:
        ctx.record("unsupported_property_payload", body, interpretation="OPEN")
        ctx.issue("OPEN", "unsupported_variant_type", owner.start)


def parse_store(ctx, owner):
    position = 0
    formats = set()
    while position < len(owner):
        size = owner.u32(position)
        if size == 0:
            ctx.record("property_store_terminal", owner.sub(position, 4))
            if position + 4 != len(owner):
                ctx.issue("OPEN", "property_store_tail_uninterpreted", owner.start + position + 4)
                ctx.record(
                    "property_store_tail", owner.sub(position + 4, len(owner) - position - 4)
                )
            return
        if size < 28:
            raise ParseFailure("invalid_property_storage_size", owner.start + position)
        storage = owner.sub(position, size)
        if storage.u32(4) != 0x53505331:
            ctx.issue("FAIL", "invalid_property_storage_version", storage.start + 4)
        fmt = str(uuid.UUID(bytes_le=storage.read(8, 16)))
        if fmt in formats:
            ctx.issue("FAIL", "duplicate_property_storage_format", storage.start + 8)
        formats.add(fmt)
        guid(ctx, storage, 8, "property_storage_format")
        ctx.record(
            "property_storage", storage, name_form="string" if fmt == STRING_NAMES else "integer"
        )
        cursor, names, terminal = 24, set(), False
        while cursor < len(storage):
            length = storage.u32(cursor)
            if length == 0:
                ctx.record("property_value_terminal", storage.sub(cursor, 4))
                terminal = True
                if cursor + 4 != len(storage):
                    ctx.issue(
                        "OPEN", "property_storage_tail_uninterpreted", storage.start + cursor + 4
                    )
                    ctx.record(
                        "property_storage_tail", storage.sub(cursor + 4, len(storage) - cursor - 4)
                    )
                break
            if length < 13:
                raise ParseFailure("invalid_property_value_size", storage.start + cursor)
            value = storage.sub(cursor, length)
            ctx.charge("properties", 1, value.start)
            if value.num(8, "B"):
                ctx.issue("FAIL", "property_nonzero_reserved", value.start + 8)
            data_offset = 9
            if fmt == STRING_NAMES:
                name_size = value.u32(4)
                if name_size < 2 or name_size % 2:
                    raise ParseFailure("invalid_property_name_size", value.start + 4)
                name_span = value.sub(9, name_size)
                if name_span.read(name_size - 2, 2) != b"\0\0":
                    raise ParseFailure("missing_property_name_terminator", name_span.end - 2)
                name, _ = decode(ctx, name_span, "utf-16-le", "property_name", terminated=True)
                identity = name_span.read(0, name_size)
                if name is not None and "\0" in name:
                    ctx.issue("OPEN", "property_name_embedded_nul", name_span.start)
                data_offset += name_size
            else:
                identity = value.u32(4)
            if identity in names:
                ctx.issue("FAIL", "duplicate_property_name", value.start + 4)
            names.add(identity)
            rec = ctx.record("property_value", value, name_redacted=not ctx.show_text)
            if ctx.show_text and fmt != STRING_NAMES:
                rec["property_id"] = identity
            typed(ctx, value.sub(data_offset, length - data_offset))
            cursor += length
        if not terminal:
            raise ParseFailure("missing_property_value_terminal", storage.end)
        position += size
    raise ParseFailure("missing_property_store_terminal", owner.end)
