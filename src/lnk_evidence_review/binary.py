"""Every read belongs to an explicit half-open physical byte span."""

import hashlib
import struct

from .contracts import BudgetStop, ParseFailure


class Span:
    def __init__(self, data, start=0, size=None):
        self.data = data
        self.start = start
        self.end = len(data) if size is None else start + size
        if start < 0 or self.end < start or self.end > len(data):
            raise ParseFailure("span_out_of_bounds", max(0, start))

    def __len__(self):
        return self.end - self.start

    def check(self, offset, size):
        if offset < 0 or size < 0 or offset + size > len(self):
            raise ParseFailure("field_out_of_bounds", self.start + max(0, offset))

    def read(self, offset, size):
        self.check(offset, size)
        return self.data[self.start + offset : self.start + offset + size]

    def sub(self, offset, size):
        self.check(offset, size)
        return Span(self.data, self.start + offset, size)

    def num(self, offset, fmt):
        self.check(offset, struct.calcsize(fmt))
        return struct.unpack_from("<" + fmt, self.data, self.start + offset)[0]

    def u16(self, offset):
        return self.num(offset, "H")

    def u32(self, offset):
        return self.num(offset, "I")

    def provenance(self):
        return {
            "offset": self.start,
            "size": len(self),
            "sha256": hashlib.sha256(self.data[self.start : self.end]).hexdigest(),
        }


class Context:
    def __init__(self, limits, show_text, ansi_codepage):
        self.limits = limits
        self.show_text = show_text
        self.ansi_codepage = ansi_codepage
        self.records = []
        self.findings = []
        self.seen_findings = set()
        self.fail = self.open = False
        self.counts = {"items": 0, "extra_blocks": 0, "properties": 0, "text_bytes": 0}

    def issue(self, status, code, offset):
        if status == "FAIL":
            self.fail = True
        else:
            self.open = True
        key = (status, code, offset)
        if key in self.seen_findings:
            return
        self.seen_findings.add(key)
        if len(self.findings) < self.limits.findings:
            self.findings.append({"status": status, "code": code, "offset": offset})
        else:
            self.open = True

    def charge(self, kind, amount, offset):
        self.counts[kind] += amount
        if self.counts[kind] > getattr(self.limits, kind):
            raise BudgetStop(kind + "_budget", offset)

    def record(self, kind, span, **values):
        if len(self.records) >= self.limits.structures:
            raise BudgetStop("structures_budget", span.start)
        record = {"kind": kind, **span.provenance(), **values}
        self.records.append(record)
        return record
