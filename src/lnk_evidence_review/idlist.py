"""ItemID payloads belong to vendor namespaces, not a universal file-path grammar."""

from .contracts import ParseFailure


def parse_idlist(ctx, owner, kind="target_idlist"):
    ctx.record(kind, owner)
    position = 0
    boundaries = set()
    while position < len(owner):
        size = owner.u16(position)
        if size == 0:
            ctx.record("idlist_terminal", owner.sub(position, 2))
            if position + 2 != len(owner):
                ctx.issue("OPEN", "idlist_terminal_tail", owner.start + position + 2)
                ctx.record(
                    "idlist_uninterpreted_tail", owner.sub(position + 2, len(owner) - position - 2)
                )
            return boundaries
        if size < 2:
            raise ParseFailure("invalid_item_size", owner.start + position)
        item = owner.sub(position, size)
        ctx.charge("items", 1, item.start)
        boundaries.add(position)
        ctx.record(
            "namespace_item",
            item,
            payload_offset=item.start + 2,
            payload_size=size - 2,
            class_byte=None if size == 2 else item.num(2, "B"),
            namespace_interpretation="OPEN",
        )
        ctx.issue("OPEN", "vendor_namespace_payload_uninterpreted", item.start + 2)
        position += size
    raise ParseFailure("missing_idlist_terminal", owner.end)
