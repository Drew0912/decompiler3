"""The readable .dat listing (.debug.txt): the whole file as the VM sees it - the header, the global vars, each function's
table entry, code (offset, raw bytes, the real opcode with its operands as encoded, the meaning as a comment) and call-site
debug records, the code bytes no instruction covers, and the string pool with each string's section"""

from bisect import bisect_left
from dataclasses import astuple, dataclass
from pathlib import Path

from common.logging import log
from common.utils import quote_string
from ir.llil.llil import default_label_for_addr
from ..disasm import CommentOptions, ED9Opcode, Formatter, FormatterContext, Instruction, OperandType
from ..disasm.ed9_optable import ED9OperandType
from ..disasm.llil_dsl_comments import instruction_comments, label_comments
from .call_records import read_debug_records, record_args, record_mismatch
from .code_layout import code_order, code_start, dropped_ranges, function_extents
from .scp import CallDebugInfoTracker, OPCODE_SIZE, PUSH_ENCODED_OPS, ScpParser
from .string_pool import StringPoolSection, collect_string_refs, pool_strings, read_text, read_u32
from .types_parser import Function
from .types_scp import ScpFunctionCallDebugInfo, ScpFunctionCallDebugInfoArg, ScpGlobalVar, ScpValue

BYTES_PER_LINE      = 10                    # the longest instruction (CALL_SCRIPT: opcode, module, func, argc)
BYTES_WIDTH         = len(bytes(BYTES_PER_LINE).hex(' '))
COLUMN_GAP          = 2
ASM_WIDTH           = len('CALL_SCRIPT_NO_RETURN Str(0xFFFFFF), Str(0xFFFFFF), 255')   # the longest, in a file under 16 MB
SECTION_WIDTH       = max(len(section.name) for section in StringPoolSection)
LISTING_COMMENTS    = CommentOptions(float_bits = True, call_args = True)
OPERAND_CONTEXT     = FormatterContext()    # no names: operands print as encoded
ARG_TYPE_NAMES      = {arg_type.value: arg_type.name for arg_type in ScpFunctionCallDebugInfoArg.Type}
GLOBAL_TYPE_NAMES   = {var_type.value: var_type.name for var_type in ScpGlobalVar.Type}


@dataclass(frozen = True)
class ListingSections:
    """Which sections .debug.txt prints (ScenaDecompileConfig.debug_sections)"""
    header              : bool = True
    global_vars         : bool = True
    function_entries    : bool = True
    code                : bool = True
    call_records        : bool = True
    string_pool         : bool = True

    @property
    def empty(self) -> bool:
        return not any(astuple(self))

    @property
    def per_function(self) -> bool:
        return self.function_entries or self.code or self.call_records


def write_listing(path: Path, out_path: Path, sections: ListingSections, selected: set[int] | None = None):
    """Write path's listing to out_path; selected = the table indices that get per-function sections (None: all)"""
    if sections.empty:
        log.warning(f'{path}: every .debug.txt section is off (ScenaDecompileConfig.debug_sections)')
        lines = [ScpListing.title(path)]

    else:
        lines = ScpListing(path).lines(sections, selected)

    out_path.write_text('\n'.join(lines) + '\n', encoding = 'utf-8', newline = '\n')


class ScpListing:
    """One file loaded for its listing - unreachable code decoded and the raw debug records read, whatever the decompile
    flags are"""

    def __init__(self, path: Path):
        self.path = path
        self.parser, _ = ScpParser.load(path, round_trip = False, keep_unreachable_code = True)
        self.data = path.read_bytes()
        self.records = read_debug_records(self.parser, self.data)
        self.refs = collect_string_refs(self.data, self.parser, self.records)
        self.offset_width = len(f'{len(self.data):X}')
        self.asm_column = len(self.code_prefix(0, b''))
        self.comment_column = self.asm_column + ASM_WIDTH

        # Every decoded instruction by offset, with the functions that decoded it (in code order)
        self.decoded: dict[int, list[tuple[Instruction, Function]]] = {}
        self.unreachable = set()
        for index in code_order(self.parser.function_entries):
            func = self.parser.functions[index]
            self.unreachable.update(id(inst) for inst in ScpParser.unreachable_instructions(func))
            for inst in self.parser.code_instructions(func):
                self.decoded.setdefault(inst.offset, []).append((inst, func))

        self.offsets = sorted(self.decoded)
        self.targets = {operand.value for choices in self.decoded.values() for inst, _ in choices
                        for operand in inst.operands if operand.descriptor.type == OperandType.Offset}

    @classmethod
    def title(cls, path: Path) -> str:
        return f'.debug.txt of {path.name}'

    def lines(self, sections: ListingSections, selected: set[int] | None = None) -> list[str]:
        lines = [self.title(self.path)]
        if sections.header:
            lines += ['', *self.header_lines()]

        if sections.global_vars:
            lines += ['', *self.global_var_lines()]

        if sections.per_function:
            lines += self.function_lines(sections, selected)

        if sections.string_pool:
            lines += ['', *self.string_pool_lines()]

        return lines

    def header_lines(self) -> list[str]:
        header = self.parser.header
        return ['=== Header ===',
                f'function_entry_offset 0x{header.function_entry_offset:X}, function_count {header.function_count}, '
                f'global_var_offset 0x{header.global_var_offset:X}, global_var_count {header.global_var_count}, '
                f'dword_14 0x{header.dword_14:X}']

    def global_var_lines(self) -> list[str]:
        lines = [f'=== Global vars ({len(self.parser.global_vars)}) ===']
        for var in self.parser.global_vars:
            type_name = GLOBAL_TYPE_NAMES.get(var.type)
            lines.append(f'[{var.index}] {quote_string(var.name)}, type {int(var.type)}' + (f' ({type_name})' if type_name else ''))

        return lines

    def function_lines(self, sections: ListingSections, selected: set[int] | None) -> list[str]:
        """Each range of code once, in code order, under every function that starts there; the bytes before the first
        function as a block of their own"""
        groups: dict[int, tuple[int, list[Function]]] = {}
        for index, (start, end) in function_extents(self.parser.function_entries, self.refs.pool_start).items():
            groups.setdefault(start, (end, []))[1].append(self.parser.functions[index])

        lines = []
        start = code_start(self.parser.header)
        first_start = min(groups, default = self.refs.pool_start)
        if sections.code and start < first_start:
            lines += ['', f'=== Outside every function: 0x{start:X}..0x{first_start:X} ===', *self.raw_lines(start, first_start)]

        for start, (end, members) in groups.items():
            if selected is None or any(func.index in selected for func in members):
                lines += ['', *self.group_lines(sections, start, end, members)]

        return lines

    def group_lines(self, sections: ListingSections, start: int, end: int, members: list[Function]) -> list[str]:
        shared = len(members) > 1
        ids = ', '.join(f'0x{func.index:04X}' for func in members)
        lines = [f'=== {" + ".join(func.name for func in members)} (id{"s" if shared else ""} {ids}, '
                 f'{"shared " if shared else ""}code 0x{start:X}..0x{end:X}) ===']

        owners = {func.index: f'{func.name} ' if shared else '' for func in members}   # names a shared range's member
        pairings = [(func, *self.pairing(func)) for func in members] if sections.call_records else []
        if sections.function_entries:
            lines += [(f'{func.name}: ' if shared else '') + self.entry_text(func) for func in members]

        if sections.code:
            tags = {}
            for func, call_offsets, _ in pairings:
                for i, offset in call_offsets.items():
                    tags.setdefault(offset, []).append(f'{owners[func.index]}record {i}: {self.record_text(self.records[func.index][i])}')

            lines += ['--- code ---', *self.code_lines(start, end, members, tags)]

        for func, call_offsets, note in pairings:
            records = self.records[func.index]
            lines.append(f'--- {owners[func.index]}call records ({len(records)}) ---' + (f'  ; {note}' if note else ''))
            for i, record in enumerate(records):
                lines.append(f'[{i:2}] {self.record_text(record)}' + (f' @ 0x{call_offsets[i]:X}' if i in call_offsets else ''))

        return lines

    def entry_text(self, func: Function) -> str:
        entry = self.parser.function_entries[func.index]
        params = ', '.join(Formatter.format_param(i, param) for i, param in enumerate(func.params))
        return (f'code 0x{entry.offset:X}; {entry.param_count} params [{params}]; {entry.default_params_count} defaults; '
                f'common {entry.is_common_func}; byte06 {entry.byte06}; name {quote_string(func.name)} '
                f'(pool 0x{ScpParser.get_string_offset(entry.name_offset):X}, hash 0x{entry.name_hash:08X}); '
                f'{entry.debug_info_count} debug records at 0x{entry.debug_info_offset:X}')

    def code_lines(self, start: int, end: int, members: list[Function], tags: dict[int, list[str]]) -> list[str]:
        """Every decoded instruction in [start, end) - a member's decoding first - and the ranges none covers"""
        indices = {func.index for func in members}
        listed = []
        for offset in self.offsets[bisect_left(self.offsets, start):bisect_left(self.offsets, end)]:
            choices = self.decoded[offset]
            listed.append(next(((inst, func) for inst, func in choices if func.index in indices), choices[0]))

        gaps = [(gap_start, gap_end) for gap_start, gap_end, _ in dropped_ranges([inst for inst, _ in listed], start, end)]
        lines = []
        for inst, func in listed:
            while gaps and gaps[0][0] < inst.offset:
                lines += self.raw_lines(*gaps.pop(0), 'not decoded')

            if inst.offset in self.targets:
                depth = label_comments(func.stack_layout, inst.offset, LISTING_COMMENTS)
                lines.append(self.with_comments(f'{"":<{self.asm_column}}{default_label_for_addr(inst.offset)}:', depth))

            text, notes = self.asm_text(inst)
            comments = ['unreachable'] if id(inst) in self.unreachable else []
            if func.index not in indices:
                comments.append(f'decoded by {func.name}')

            others = [other.name for _, other in self.decoded[inst.offset] if other is not func]
            if others:
                comments.append(f'also decoded by {", ".join(others)}')

            comments += notes + instruction_comments(func.stack_layout, inst, LISTING_COMMENTS)
            lines.append(self.with_comments(self.code_prefix(inst.offset, self.data[inst.offset:inst.offset + inst.size]) + text, comments))
            lines += [self.with_comments('', [f'  {tag}']) for tag in tags.get(inst.offset, [])]

        for gap in gaps:
            lines += self.raw_lines(*gap, 'not decoded')

        return lines

    def asm_text(self, inst: Instruction) -> tuple[str, list[str]]:
        """The real opcode with its operands as encoded, and their meaning"""
        words = iter(read_u32(self.data, position) for position in ScpParser.value_positions(inst))
        if inst.opcode in PUSH_ENCODED_OPS:
            word = next(words)
            typed, text = self.value_text(word)
            if inst.opcode == ED9Opcode.PUSH_CURRENT_FUNC_ID:
                text = f'func id: {self.parser.get_func_name_from_func_id(word & ScpValue.PAYLOAD_MASK)}'

            elif inst.opcode == ED9Opcode.PUSH_RET_ADDR:
                text = f'return address -> {default_label_for_addr(inst.operands[0].value)}'

            return f'{ED9Opcode.PUSH.name} {self.data[inst.offset + OPCODE_SIZE]}, {typed}', [text] if text else []

        operands = []
        notes = []
        for operand in inst.operands:
            kind = operand.descriptor.type
            if kind == OperandType.Offset:
                operands.append(f'0x{operand.value:X}')
                notes.append(f'-> {default_label_for_addr(operand.value)}')

            elif kind == ED9OperandType.Func:
                operands.append(str(operand.value))
                notes.append(self.parser.get_func_name_from_func_id(operand.value))

            elif kind == ED9OperandType.Value:
                typed, text = self.value_text(next(words))
                operands.append(typed)
                notes += [text] if text else []

            else:
                operands.append(operand.descriptor.format_operand(operand, OPERAND_CONTEXT))
                name = self.parser.get_global_name_from_index(operand.value) if kind == ED9OperandType.GlobalVar else None
                notes += [quote_string(name)] if name is not None else []

        return f'{inst.mnemonic} {", ".join(operands)}'.rstrip(), notes

    def value_text(self, word: int) -> tuple[str, str | None]:
        """An encoded ScpValue as Type(payload), and a string's text (read like the pool section, invalid bytes shown)"""
        offset = ScpParser.get_string_offset(word)
        if offset is not None:
            return f'Str(0x{offset:X})', quote_string(read_text(self.data, offset))

        value = ScpValue().from_value(word)
        match value.type:
            case ScpValue.Type.Float:
                return f'Float({ScpValue.float_literal(value.value)})', None

            case ScpValue.Type.Integer:
                return f'Int({value.value})', None

        return f'Raw(0x{value.value:X})', None

    def pairing(self, func: Function) -> tuple[dict[int, int], str | None]:
        """Each record's call offset when every record holds what its call gets (content only), else why not"""
        pairs = CallDebugInfoTracker.replay(self.parser.code_instructions(func), self.parser.get_func_argc)
        records = self.records[func.index]
        if len(pairs) != len(records):
            return {}, f'records not paired: {len(pairs)} calls, {len(records)} records'

        for i, ((call, _), record) in enumerate(zip(pairs, records)):
            problem = record_mismatch(self.data, call, record)
            if problem is not None:
                return {}, f'records not paired: record {i} differs from its call ({problem})'

        return {i: offset for i, (_, offset) in enumerate(pairs)}, None

    def record_text(self, record: ScpFunctionCallDebugInfo) -> str:
        args = []
        for arg_type, word in record_args(self.data, record):
            if arg_type == ScpFunctionCallDebugInfoArg.Type.Constant:
                typed, text = self.value_text(word)
                args.append(text or typed)

            else:
                args.append(ARG_TYPE_NAMES.get(arg_type, f'type {arg_type}'))

        is_local = record.call_type == ScpFunctionCallDebugInfo.CallType.Local
        callee = f' {self.parser.get_func_name_from_func_id(record.func_id)}' if is_local else ''
        return f'{record.call_type.name}{callee}({", ".join(args)})'

    def string_pool_lines(self) -> list[str]:
        sections = {}
        for section, offsets in self.refs.sections():
            for offset in offsets:
                sections.setdefault(offset, section.name.lower())

        offsets = pool_strings(self.data, self.refs.pool_start)
        lines = [f'=== String pool ({len(offsets)} strings from 0x{self.refs.pool_start:X}) ===']
        for offset in offsets:
            section = sections.get(offset, '-')
            lines.append(f'0x{offset:0{self.offset_width}X}{" " * COLUMN_GAP}{section:<{SECTION_WIDTH}}{" " * COLUMN_GAP}'
                         f'{quote_string(read_text(self.data, offset))}')

        return lines

    def raw_lines(self, start: int, end: int, note: str | None = None) -> list[str]:
        """[start, end) as raw bytes, BYTES_PER_LINE a line"""
        return [self.with_comments(self.code_prefix(offset, self.data[offset:min(offset + BYTES_PER_LINE, end)]), [note] if note else [])
                for offset in range(start, end, BYTES_PER_LINE)]

    def code_prefix(self, offset: int, raw: bytes) -> str:
        return f'0x{offset:0{self.offset_width}X}{" " * COLUMN_GAP}{raw.hex(" "):<{BYTES_WIDTH}}{" " * COLUMN_GAP}'

    def with_comments(self, text: str, comments: list[str]) -> str:
        return f'{text:<{self.comment_column}} ; {", ".join(comments)}' if comments else text.rstrip()
