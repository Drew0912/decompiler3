"""Whether a logic round keeps the source's game logic (docs/ROUND_TRIP_POLICY.md): each function's fingerprint,
the global table, header dword_14, and the functions printed in the HLIL DSL"""

from dataclasses import dataclass

from falcom.ed9.structs.fingerprint import function_fingerprint, function_fingerprint_without_line_markers
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.assembler.function import Function
from .results import CheckResult


@dataclass
class LogicSnapshot:
    """Everything the 'game logic' definition covers for one decompile: per-function (fingerprint,
    is_common_func) by name, the global table in index order (bytecode refers to globals by index,
    so order matters), and header dword_14. The functions in without_line_markers (those the source's
    decompile printed in the HLIL DSL, which writes no line markers) are fingerprinted without them"""

    fingerprints: dict[str, tuple]
    globals_table: list[tuple[str, int]]
    dword_14: int
    without_line_markers: frozenset[str] = frozenset()

    @classmethod
    def of(cls, parser: ScpParser, functions: list[Function],
           without_line_markers: frozenset[str] = frozenset()) -> LogicSnapshot:
        fingerprints = {func.name: (cls.fingerprint(parser, func, without_line_markers), func.is_common_func)
                        for func in functions}
        globals_table = [(g.name, int(g.type)) for g in parser.global_vars]
        return cls(fingerprints, globals_table, parser.header.dword_14, without_line_markers)

    @classmethod
    def fingerprint(cls, parser: ScpParser, func: Function, without_line_markers: frozenset[str]) -> tuple:
        if func.name in without_line_markers:
            return function_fingerprint_without_line_markers(parser, func)

        return function_fingerprint(parser, func)


def compare_logic(source: LogicSnapshot, other: LogicSnapshot) -> CheckResult:
    """Everything the game logic definition covers, source vs one recompiled round; both snapshots take the source
    decompile's HLIL names as their without_line_markers"""
    failures = []

    missing = sorted(set(source.fingerprints) - set(other.fingerprints))
    extra = sorted(set(other.fingerprints) - set(source.fingerprints))
    if missing:
        failures.append(f'missing after recompile: {missing}')

    if extra:
        failures.append(f'extra after recompile: {extra}')

    for name in sorted(set(source.fingerprints) & set(other.fingerprints)):
        src_fingerprint, src_common = source.fingerprints[name]
        other_fingerprint, other_common = other.fingerprints[name]

        if src_fingerprint != other_fingerprint:
            kind = ' (without line markers)' if name in source.without_line_markers else ''
            failures.append(f'{name}: fingerprint{kind} differs after recompile')

        if src_common != other_common:
            failures.append(f'{name}: is_common_func {src_common} != {other_common}')

    if source.globals_table != other.globals_table:
        failures.append(f'global table differs: {source.globals_table} != {other.globals_table}')

    if source.dword_14 != other.dword_14:
        failures.append(f'header dword_14 {source.dword_14} != {other.dword_14}')

    summary = (f'{len(source.fingerprints)} functions compared '
               f'({len(source.without_line_markers)} without line markers)')
    return CheckResult.build('logic preserved', summary, failures)


def check_mode(source_names: frozenset[str], round_names: frozenset[str]) -> CheckResult:
    """A round's decompile prints exactly the source decompile's functions in the HLIL DSL"""
    failures = []
    if lost := sorted(source_names - round_names):
        failures.append(f'no longer HLIL: {lost}')

    if gained := sorted(round_names - source_names):
        failures.append(f'newly HLIL: {gained}')

    return CheckResult.build('mode', f'{len(source_names)} functions HLIL, as in the source decompile', failures)
