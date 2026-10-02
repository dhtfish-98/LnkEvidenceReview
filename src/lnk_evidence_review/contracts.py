"""Finite resource and evidence contracts; caller assertions are not authentication."""

from dataclasses import asdict, dataclass, fields


@dataclass(frozen=True)
class Limits:
    input_bytes: int = 4 * 1024 * 1024
    structures: int = 4096
    items: int = 512
    extra_blocks: int = 128
    properties: int = 512
    text_bytes: int = 262144
    text_field_bytes: int = 65536
    findings: int = 256
    report_bytes: int = 2 * 1024 * 1024

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            maximum = field.default
            minimum = 2048 if field.name == "report_bytes" else 1
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError("invalid_limits")


def limits_dict(limits):
    return asdict(limits)


ASSUMPTIONS = {
    "target_authenticity": "OPEN",
    "target_resolution_or_execution": "OPEN",
    "source_authenticity": "OPEN",
    "metadata_currentness": "OPEN",
    "maliciousness_or_safety": "OPEN",
    "cvp_eligibility": "OPEN",
}


class ParseFailure(Exception):
    def __init__(self, code, offset):
        self.code, self.offset = code, offset


class BudgetStop(Exception):
    def __init__(self, code, offset):
        self.code, self.offset = code, offset
