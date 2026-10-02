"""Owner-relative offsets, independent local/network branches, no target resolution."""

from .contracts import ParseFailure
from .text import cstring


def volume(ctx, owner):
    if len(owner) <= 16:
        raise ParseFailure("invalid_volume_size", owner.start)
    drive = owner.u32(4)
    if drive > 6:
        ctx.issue("FAIL", "invalid_drive_type", owner.start + 4)
    label = owner.u32(12)
    if label == 20:
        cstring(ctx, owner, owner.u32(16), "utf-16-le", "volume_label_unicode", 20)
    else:
        cstring(ctx, owner, label, "ansi", "volume_label_ansi", 16)
    record = ctx.record("volume_id", owner, drive_type=drive, serial_redacted=not ctx.show_text)
    ctx.record("drive_serial", owner.sub(8, 4), value_redacted=not ctx.show_text)
    if ctx.show_text:
        record["declared_drive_serial"] = owner.u32(8)


def network(ctx, owner):
    if len(owner) < 20:
        raise ParseFailure("invalid_network_size", owner.start)
    flags, net, device, provider = (owner.u32(i) for i in (4, 8, 12, 16))
    if flags & ~3:
        ctx.issue("OPEN", "unsupported_network_flags", owner.start + 4)
    extended = net > 20
    # The Unicode extension is selected by NetNameOffset; an ANSI device name
    # naturally follows the ANSI network name and can itself start after 0x14.
    device_extended = extended and (bool(flags & 1) or net >= 28)
    minimum = 28 if device_extended else 24 if extended else 20
    owner.check(0, minimum)
    if extended and not flags & 1:
        if not device_extended:
            ctx.issue("OPEN", "ambiguous_single_unicode_offset_layout", owner.start + 8)
        elif owner.u32(24):
            ctx.issue("OPEN", "inactive_unicode_device_offset_nonzero", owner.start + 24)
    if flags & 1:
        cstring(ctx, owner, device, "ansi", "network_device_ansi", minimum)
    elif device:
        ctx.issue("FAIL", "device_offset_without_flag", owner.start + 12)
    if flags & 2:
        if provider not in {value << 16 for value in range(0x1A, 0x44) if value != 0x28}:
            ctx.issue("OPEN", "unsupported_network_provider", owner.start + 16)
    elif provider:
        ctx.issue("OPEN", "network_provider_without_flag", owner.start + 16)
    cstring(ctx, owner, net, "ansi", "network_name_ansi", minimum)
    if extended:
        cstring(ctx, owner, owner.u32(20), "utf-16-le", "network_name_unicode", minimum)
        if flags & 1:
            cstring(ctx, owner, owner.u32(24), "utf-16-le", "network_device_unicode", minimum)
    ctx.record(
        "network_link_info",
        owner,
        flags=flags,
        provider_type=provider,
        unicode_net_offset_present=extended,
        unicode_device_offset_present=device_extended,
    )


def parse_linkinfo(ctx, owner, ignored):
    size = owner.u32(0)
    if size != len(owner) or size < 28:
        raise ParseFailure("invalid_linkinfo_size", owner.start)
    header = owner.u32(4)
    if header != 28 and header < 36:
        raise ParseFailure("invalid_linkinfo_header_size", owner.start + 4)
    owner.check(0, header)
    if header > 36:
        ctx.issue("OPEN", "unsupported_linkinfo_header_extension", owner.start + 36)
        ctx.record("linkinfo_header_extension", owner.sub(36, header - 36))
    flags, volume_offset, local_offset, network_offset, suffix_offset = (
        owner.u32(i) for i in (8, 12, 16, 20, 24)
    )
    if flags & ~3:
        ctx.issue("OPEN", "unsupported_linkinfo_flags", owner.start + 8)
    ctx.record(
        "link_info", owner, flags=flags, header_size=header, resolution_ignored_by_header=ignored
    )
    ranges = []
    for enabled, offset, kind, parser in (
        (bool(flags & 1), volume_offset, "volume", volume),
        (bool(flags & 2), network_offset, "network", network),
    ):
        if enabled:
            if offset < header or offset + 4 > len(owner):
                raise ParseFailure(
                    "substructure_offset_out_of_bounds", owner.start + max(0, offset)
                )
            length = owner.u32(offset)
            sub = owner.sub(offset, length)
            parser(ctx, sub)
            ranges.append((offset, offset + length, kind))
        elif offset:
            ctx.issue("FAIL", "substructure_offset_without_flag", owner.start + offset)
    if len(ranges) == 2 and max(ranges[0][0], ranges[1][0]) < min(ranges[0][1], ranges[1][1]):
        ctx.issue("OPEN", "overlapping_linkinfo_substructures", owner.start)
    texts = []
    if flags & 1:
        texts.append((local_offset, "ansi", "local_base_path_ansi"))
    elif local_offset:
        ctx.issue("FAIL", "local_path_offset_without_flag", owner.start + 16)
    texts.append((suffix_offset, "ansi", "common_path_suffix_ansi"))
    if header >= 36:
        local_unicode, suffix_unicode = owner.u32(28), owner.u32(32)
        if flags & 1:
            texts.append((local_unicode, "utf-16-le", "local_base_path_unicode"))
        elif local_unicode:
            ctx.issue("FAIL", "unicode_local_path_offset_without_flag", owner.start + 28)
        if suffix_unicode:
            texts.append((suffix_unicode, "utf-16-le", "common_path_suffix_unicode"))
    for offset, encoding, kind in texts:
        value, record = cstring(ctx, owner, offset, encoding, kind, header)
        del value
        end = offset + record["size"]
        if any(max(offset, start) < min(end, stop) for start, stop, _ in ranges):
            ctx.issue("OPEN", "string_overlaps_linkinfo_substructure", owner.start + offset)
