"""What a check reports: its status, a summary and its detail lines"""

from dataclasses import dataclass, field
from enum import IntEnum


MAX_DETAILS = 10


class Status(IntEnum):
    PASS = 0
    WARN = 1
    FAIL = 2


@dataclass
class CheckResult:
    name    : str
    status  : Status
    summary : str
    details : list[str] = field(default_factory=list)

    @classmethod
    def build(cls, name: str, summary: str, failures: list[str], warnings: list[str] | None = None) -> CheckResult:
        warnings = warnings or []

        if failures:
            status = Status.FAIL
        elif warnings:
            status = Status.WARN
        else:
            status = Status.PASS

        return cls(name, status, summary, failures + warnings)


def exception_text(exc: Exception) -> str:
    return f'{type(exc).__name__}: {ascii(str(exc))}'
