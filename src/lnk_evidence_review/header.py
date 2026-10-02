"""MS-SHLLINK 2.1: persisted declarations, never observed target facts."""

import uuid

from .contracts import ParseFailure


FLAG_NAMES = (
    "HasLinkTargetIDList",
    "HasLinkInfo",
    "HasName",
    "HasRelativePath",
    "HasWorkingDir",
    "HasArguments",
    "HasIconLocation",
    "IsUnicode",
    "ForceNoLinkInfo",
    "HasExpString",
    "RunInSeparateProcess",
    "Unused1",
    "HasDarwinID",
    "RunAsUser",
    "HasExpIcon",
    "NoPidlAlias",
    "Unused2",
    "RunWithShimLayer",
    "ForceNoLinkTrack",
    "EnableTargetMetadata",
    "DisableLinkPathTracking",
    "DisableKnownFolderTracking",
    "DisableKnownFolderAlias",
    "AllowLinkToLink",
    "UnaliasOnSave",
    "PreferEnvironmentPath",
    "KeepLocalIDListForUNCTarget",
)


def parse_header(ctx, owner):
    header = owner.sub(0, 76)
    if header.u32(0) != 76:
        raise ParseFailure("invalid_header_size", header.start)
    clsid = str(uuid.UUID(bytes_le=header.read(4, 16)))
    if clsid != "00021401-0000-0000-c000-000000000046":
        raise ParseFailure("invalid_link_clsid", header.start + 4)
    flags = header.u32(20)
    attributes = header.u32(24)
    if flags >> len(FLAG_NAMES):
        ctx.issue("OPEN", "unsupported_link_flags", header.start + 20)
    if attributes & 0x48:
        ctx.issue("FAIL", "nonzero_reserved_attributes", header.start + 24)
    if attributes & 0x80 and attributes != 0x80:
        ctx.issue("FAIL", "normal_attribute_combined", header.start + 24)
    if attributes >> 15:
        ctx.issue("OPEN", "unsupported_file_attributes", header.start + 24)
    if header.u16(66) or header.u32(68) or header.u32(72):
        ctx.issue("FAIL", "nonzero_header_reserved", header.start + 66)
    key, modifiers = header.num(64, "B"), header.num(65, "B")
    if (
        not (
            key == 0
            or 0x30 <= key <= 0x39
            or 0x41 <= key <= 0x5A
            or 0x70 <= key <= 0x87
            or key in (0x90, 0x91)
        )
        or modifiers & ~7
    ):
        ctx.issue("FAIL", "invalid_hotkey", header.start + 64)
    ctx.record(
        "header",
        header,
        link_flags=flags,
        flag_names=[name for index, name in enumerate(FLAG_NAMES) if flags & (1 << index)],
        declared_file_attributes=attributes,
        declared_creation_filetime=header.num(28, "Q"),
        declared_access_filetime=header.num(36, "Q"),
        declared_write_filetime=header.num(44, "Q"),
        declared_file_size_low32=header.u32(52),
        declared_icon_index=header.num(56, "i"),
        show_command=header.u32(60),
        effective_show_command=header.u32(60) if header.u32(60) in (1, 3, 7) else 1,
        hotkey_key=key,
        hotkey_modifiers=modifiers,
    )
    return flags
