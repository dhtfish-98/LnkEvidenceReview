"""Independent defensive Shell Link evidence parser."""

from .contracts import Limits
from .review import encode_report, review_bytes

__all__ = ["Limits", "encode_report", "review_bytes"]
__version__ = "0.1.1"

__author__ = "dhtfish98"
