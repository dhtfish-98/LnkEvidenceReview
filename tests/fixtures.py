"""Synthetic benign binary layouts; never a launchable target or payload writer."""

import struct
import uuid


def u16(value):
    return struct.pack("<H", value)


def u32(value):
    return struct.pack("<I", value)


def header(flags=0):
    data = bytearray(76)
    data[:4] = u32(76)
    data[4:20] = uuid.UUID("00021401-0000-0000-c000-000000000046").bytes_le
    data[20:24] = u32(flags)
    data[60:64] = u32(1)
    return bytes(data)


def counted(text, unicode=True):
    raw = text.encode("utf-16-le" if unicode else "cp1252")
    return u16(len(raw) // (2 if unicode else 1)) + raw


def block(signature, payload):
    return u32(8 + len(payload)) + u32(signature) + payload


def environment(signature=0xA0000001, ansi="%EXAMPLE%\\note.txt", unicode="%EXAMPLE%\\note.txt"):
    left = ansi.encode("ascii") + b"\0"
    right = unicode.encode("utf-16-le") + b"\0\0"
    return block(signature, left.ljust(260, b"\0") + right.ljust(520, b"\0"))


def linkinfo(local=True, network=True, unicode=True):
    # Independently append each region and store its measured relative offset.
    size = 36 if unicode else 28
    data = bytearray(size)
    data[4:8] = u32(size)
    data[8:12] = u32(int(local) | (2 * int(network)))
    if local:
        label = b"VOL\0"
        volume = u32(16 + len(label)) + u32(3) + u32(123) + u32(16) + label
        data[12:16] = u32(len(data))
        data += volume
        data[16:20] = u32(len(data))
        data += b"C:\\test\0"
    if network:
        net = b"\\\\example.invalid\\share\0"
        device = b"Z:\0"
        unicode_net = "\\\\example.invalid\\share".encode("utf-16-le") + b"\0\0"
        unicode_device = "Z:".encode("utf-16-le") + b"\0\0"
        base = 28 if unicode else 20
        common = bytearray(base)
        common[4:8] = u32(3)
        common[8:12] = u32(base)
        common[12:16] = u32(base + len(net))
        common[16:20] = u32(0x200000)
        if unicode:
            common[20:24] = u32(base + len(net) + len(device))
            common[24:28] = u32(base + len(net) + len(device) + len(unicode_net))
        common += net + device
        if unicode:
            common += unicode_net + unicode_device
        common[:4] = u32(len(common))
        data[20:24] = u32(len(data))
        data += common
    data[24:28] = u32(len(data))
    data += b"note.txt\0"
    if unicode:
        if local:
            data[28:32] = u32(len(data))
            data += "C:\\test".encode("utf-16-le") + b"\0\0"
        data[32:36] = u32(len(data))
        data += "note.txt".encode("utf-16-le") + b"\0\0"
    data[:4] = u32(len(data))
    return bytes(data)


def typed(typ, payload):
    return u16(typ) + u16(0) + payload


def property_store(values, string_names=False, fmt=None):
    ident = fmt or (
        "d5cdd505-2e9c-101b-9397-08002b2cf9ae"
        if string_names
        else "000214a0-0000-0000-c000-000000000046"
    )
    payload = b""
    for name, value in values:
        if string_names:
            name = name.encode("utf-16-le") + b"\0\0"
            content = u32(len(name)) + b"\0" + name + value
        else:
            content = u32(name) + b"\0" + value
        payload += u32(4 + len(content)) + content
    storage = (
        u32(28 + len(payload)) + u32(0x53505331) + uuid.UUID(ident).bytes_le + payload + u32(0)
    )
    return block(0xA0000009, storage + u32(0))


def independent_outline(data):
    # Separate reference parser: no import or calls into the new implementation.
    def integer(at, width):
        if at < 0 or at + width > len(data):
            raise ValueError("truncated_reference")
        return int.from_bytes(data[at : at + width], "little")

    if integer(0, 4) != 76:
        raise ValueError("header")
    flags, cursor = integer(20, 4), 76
    result = {"flags": flags, "strings": {}, "extra": []}
    if flags & 1:
        cursor += 2 + integer(cursor, 2)
    if flags & 2:
        size = integer(cursor, 4)
        suffix = integer(cursor + 24, 4)
        stop = data.index(b"\0", cursor + suffix, cursor + size)
        result["suffix"] = data[cursor + suffix : stop].decode("ascii")
        cursor += size
    for bit, name in (
        (4, "name"),
        (8, "relative_path"),
        (16, "working_directory"),
        (32, "arguments"),
        (64, "icon_location"),
    ):
        if flags & bit:
            count = integer(cursor, 2)
            width = 2 if flags & 128 else 1
            result["strings"][name] = data[cursor + 2 : cursor + 2 + count * width].decode(
                "utf-16-le" if width == 2 else "ascii"
            )
            cursor += 2 + count * width
    while integer(cursor, 4) >= 4:
        size = integer(cursor, 4)
        if size < 8 or cursor + size > len(data):
            raise ValueError("block")
        result["extra"].append((cursor, size, integer(cursor + 4, 4)))
        cursor += size
    result["terminal"] = cursor
    return result
