"""All eleven MS-SHLLINK ExtraData envelopes; unknown envelopes retain provenance."""

from .contracts import ParseFailure
from .idlist import parse_idlist
from .property_store import parse_store
from .text import decode, guid


KINDS = {
    0xA0000001: ("environment", 788),
    0xA0000002: ("console", 204),
    0xA0000003: ("tracker", 96),
    0xA0000004: ("console_codepage", 12),
    0xA0000005: ("special_folder", 16),
    0xA0000006: ("darwin", 788),
    0xA0000007: ("icon_environment", 788),
    0xA0000008: ("shim", None),
    0xA0000009: ("property_store", None),
    0xA000000B: ("known_folder", 28),
    0xA000000C: ("vista_idlist", None),
}


def folder_offset(ctx, block, offset, target_boundaries):
    value = block.u32(offset)
    if target_boundaries is None:
        ctx.issue("OPEN", "folder_offset_requires_target_idlist", block.start + offset)
    elif value not in target_boundaries:
        ctx.issue("FAIL", "folder_offset_not_item_boundary", block.start + offset)
    return value


def console(ctx, block, rec):
    fill, popup = block.u16(8), block.u16(10)
    if (fill | popup) & ~0xFF:
        ctx.issue("OPEN", "unsupported_console_fill_attributes", block.start + 8)
    rec.update(
        fill_attributes=fill,
        popup_fill_attributes=popup,
        screen_buffer=[block.num(12, "h"), block.num(14, "h")],
        window_size=[block.num(16, "h"), block.num(18, "h")],
        window_origin=[block.num(20, "h"), block.num(22, "h")],
        font_size=block.u32(32),
        font_family=block.u32(36),
        font_weight=block.u32(40),
        cursor_size=block.u32(108),
        full_screen=block.u32(112) != 0,
        quick_edit=block.u32(116) != 0,
        insert_mode=block.u32(120) != 0,
        auto_position=block.u32(124) != 0,
        history_buffer_size=block.u32(128),
        history_buffer_count=block.u32(132),
        history_no_dup=block.u32(136) != 0,
        color_table=[block.u32(140 + index * 4) for index in range(16)],
    )
    if block.u32(36) & ~0xFF or block.u32(36) & 0xF0 not in (0, 0x10, 0x20, 0x30, 0x40, 0x50):
        ctx.issue("OPEN", "unsupported_console_font_family", block.start + 36)
    decode(ctx, block.sub(44, 64), "utf-16-le", "console_face_name", terminated=True, fixed=True)


def parse_extra_body(ctx, block, signature, target_boundaries):
    kind, exact = KINDS[signature]
    if exact is not None and len(block) != exact:
        raise ParseFailure("invalid_known_extra_size", block.start)
    minimum = {"shim": 136, "property_store": 12, "vista_idlist": 10}.get(kind, 8)
    if len(block) < minimum:
        raise ParseFailure("invalid_known_extra_minimum_size", block.start)
    rec = ctx.record("extra_" + kind, block, signature=signature)
    if kind in ("environment", "icon_environment", "darwin"):
        decode(ctx, block.sub(8, 260), "ansi", kind + "_ansi", terminated=True, fixed=True)
        decode(
            ctx, block.sub(268, 520), "utf-16-le", kind + "_unicode", terminated=True, fixed=True
        )
        if kind == "darwin":
            ctx.issue("OPEN", "darwin_descriptor_interpretation_unsupported", block.start + 8)
    elif kind == "console":
        console(ctx, block, rec)
    elif kind == "tracker":
        if block.u32(8) != 88 or block.u32(12) != 0:
            ctx.issue("FAIL", "invalid_tracker_length_or_version", block.start + 8)
        decode(ctx, block.sub(16, 16), "ansi", "tracker_machine_id", terminated=True, fixed=True)
        for offset, name in (
            (32, "droid_volume"),
            (48, "droid_file"),
            (64, "birth_volume"),
            (80, "birth_file"),
        ):
            guid(ctx, block, offset, name)
    elif kind == "console_codepage":
        rec["display_codepage_declaration"] = block.u32(8)
        rec["used_for_ansi_decoding"] = False
    elif kind == "special_folder":
        rec["special_folder_id"] = block.u32(8)
        rec["target_idlist_offset"] = folder_offset(ctx, block, 12, target_boundaries)
    elif kind == "known_folder":
        guid(ctx, block, 8, "known_folder_id")
        rec["target_idlist_offset"] = folder_offset(ctx, block, 24, target_boundaries)
    elif kind == "shim":
        if (len(block) - 8) % 2:
            raise ParseFailure("odd_shim_unicode_size", block.start + 8)
        decode(
            ctx,
            block.sub(8, len(block) - 8),
            "utf-16-le",
            "shim_layer",
            terminated=True,
            fixed=True,
        )
    elif kind == "property_store":
        parse_store(ctx, block.sub(8, len(block) - 8))
    elif kind == "vista_idlist":
        parse_idlist(ctx, block.sub(8, len(block) - 8), "vista_target_idlist")


def parse_extras(ctx, owner, position, target_boundaries):
    signatures = set()
    while position < len(owner):
        size = owner.u32(position)
        if size < 4:
            ctx.record("extra_terminal", owner.sub(position, 4), terminal_value=size)
            if position + 4 < len(owner):
                ctx.issue("OPEN", "bytes_after_extra_terminal", owner.start + position + 4)
                ctx.record(
                    "post_terminal_bytes", owner.sub(position + 4, len(owner) - position - 4)
                )
            return signatures
        if size < 8:
            raise ParseFailure("invalid_extra_block_size", owner.start + position)
        block = owner.sub(position, size)
        ctx.charge("extra_blocks", 1, block.start)
        signature = block.u32(4)
        if signature in signatures:
            ctx.issue("OPEN", "duplicate_extra_signature", block.start + 4)
        signatures.add(signature)
        if signature in KINDS:
            try:
                parse_extra_body(ctx, block, signature, target_boundaries)
            except ParseFailure as error:
                ctx.issue("FAIL", error.code, error.offset)
                ctx.record("malformed_known_extra", block, signature=signature)
        else:
            ctx.record("unknown_extra", block, signature=signature, interpretation="OPEN")
            ctx.issue("OPEN", "unknown_extra_signature", block.start + 4)
        position += size
    raise ParseFailure("missing_extra_terminal", owner.end)
