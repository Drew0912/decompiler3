"""Two files' call-site debug records compared function by function, and a record's text in a check's lines"""

from dc3 import fileio
from falcom.ed9.structs.call_debug_records import RecordView, read_debug_records, record_view
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.structs.scp_types import ScpFunctionCallDebugInfoArg, ScpValue


def compare_file_records(original: bytes, rebuilt: bytes) -> list[str]:
    """One line per function whose records differ between the original and the rebuilt file - its first difference -
    and per function only one file has; functions match by name, so a shifted table still compares"""
    original_views, rebuilt_views = file_record_views(original), file_record_views(rebuilt)
    lines = []
    for name, views in original_views.items():
        if name not in rebuilt_views:
            lines.append(f'{name}: not in the rebuilt file')
            continue

        difference = first_record_difference(views, rebuilt_views[name])
        if difference is not None:
            lines.append(f'{name} {difference}')

    lines += [f'{name}: not in the original' for name in rebuilt_views if name not in original_views]
    return lines


def file_record_views(data: bytes) -> dict[str, list[RecordView]]:
    """Each function's record views by name, in table order: the header, table and raw records only, no disassembly"""
    with fileio.FileStream(data) as fs:
        parser = ScpParser(fs)
        parser.round_trip = False   # the table and names only: the raw records come from data
        parser.parse()

    names = [func.name for func in parser.functions]
    return {name: [record_view(data, record, names) for record in records]
            for name, records in zip(names, read_debug_records(parser, data))}


def first_record_difference(original: list[RecordView], rebuilt: list[RecordView]) -> str | None:
    """The first record that differs, else the first one missing from or extra in rebuilt"""
    for i, (original_view, rebuilt_view) in enumerate(zip(original, rebuilt)):
        difference = view_difference(original_view, rebuilt_view)
        if difference is not None:
            return f'record {i}: {difference}'

    if len(rebuilt) < len(original):
        return f'record {len(rebuilt)}: missing (original {view_text(original[len(rebuilt)])})'

    if len(rebuilt) > len(original):
        return f'record {len(original)}: extra ({view_text(rebuilt[len(original)])})'

    return None


def view_difference(original: RecordView, rebuilt: RecordView) -> str | None:
    """The first field rebuilt differs in: call type, callee, argument count, then each argument (counted as stored,
    a script call's name and a syscall's constants included)"""
    if rebuilt.call_type != original.call_type:
        return f'{rebuilt.call_type.name}, original {original.call_type.name}'

    if rebuilt.callee != original.callee:
        return f'callee {rebuilt.callee or 'none'}, original {original.callee or 'none'}'

    if len(rebuilt.args) != len(original.args):
        return f'{len(rebuilt.args)} args, original {len(original.args)}'

    for i, (original_arg, rebuilt_arg) in enumerate(zip(original.args, rebuilt.args)):
        if rebuilt_arg != original_arg:
            return f'arg {i} {arg_text(rebuilt_arg)}, original {arg_text(original_arg)}'

    return None


def view_text(view: RecordView) -> str:
    """A record as a missing or extra line names it: its call type, callee (a script call's name) and argument count"""
    if view.callee is not None:
        callee = view.callee
    elif view.args:
        callee = arg_text(view.args[0])     # a script call's name, a syscall's subsystem
    else:
        callee = 'none'

    return f'{view.call_type.name} {callee}, {len(view.args)} args'


def arg_text(arg: tuple[int, int | str]) -> str:
    """A record view's argument: a string's text, a constant's typed value, or a non-constant's type (and its word if
    it isn't the usual 0)"""
    arg_type, value = arg
    if isinstance(value, str):
        return ascii(value)

    if arg_type != ScpFunctionCallDebugInfoArg.Type.Constant:
        name = ScpFunctionCallDebugInfoArg.Type(arg_type).name
        return name if value == ScpFunctionCallDebugInfoArg.NON_CONSTANT_VALUE else f'{name} 0x{value:X}'

    value_type, decoded = ScpValue.decode_word(value)
    match value_type:
        case ScpValue.Type.Integer:
            return f'Int({decoded})'

        case ScpValue.Type.Float:
            return f'Float({ScpValue.float_literal(decoded)})'

    return f'Raw(0x{decoded:X})'
