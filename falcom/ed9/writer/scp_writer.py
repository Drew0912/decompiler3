"""Writer runtime for reassembling ED9 VM bytecode from decompiled Python script output"""

import inspect
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from common import fileio
from common.config import default_encoding
from common.logging import log
from ir.llil import WORD_SIZE
from ..disasm import ED9_INSTRUCTION_TABLE, ED9Opcode, ED9OperandType, ED9_FORMAT_TABLE, OperandDescriptor, OperandType
from ..parser.crc32 import hash_func_Name
from ..parser.scp import CallDebugInfoTracker, TrackedCall, TrackedValue, PUSH_CONSTANT_OPS
from ..parser.string_pool import StringPoolSection
from ..parser.types_scp import (
    ScpValue,
    RawInt,
    ScpFunctionEntry,
    ScpGlobalVar,
    ScpHeader,
    ScpParamFlags,
    ScpFunctionCallDebugInfo,
    ScpFunctionCallDebugInfoArg,
)
from ..parser.utils import str_to_bytes
from .scp_compile_check import CheckedFunction, CompileCheck, SourceSite, def_location, location_prefix
from .scp_writer_hook_registry import HookRegistry, require_function, wrapped_chain

# PUSH's leading byte - 4 in every sample script (checked by tools/scp_roundtrip_validator.py)
PUSH_SIZE_BYTE = 4

# Placeholders until a build() step fills them in; 0xFFFFFFFF is invalid, so a forgotten patch is obvious in a hex dump
UNRESOLVED_LABEL_OFFSET = 0xFFFFFFFF  # a label operand, until _relocate_code()
UNRESOLVED_FUNC_OFFSET = 0xFFFFFFFF  # entry.offset, until _compile_functions() sets it (code-relative until _relocate_code())
UNRESOLVED_STRING_OFFSET = 0xFFFFFFFF  # a string reference, until _write_string_pool()
UNRESOLVED_FUNC_INDEX = -1  # ScpFunction.index, until _build_function_table() sorts the table

STRING_OFFSET_TAG = ScpValue.Type.String << 30  # 0xC0000000 - top 2 bits of a resolved string-pool offset
NAME_OFFSET_FIELD_OFFSET = ScpFunctionEntry.SIZE - WORD_SIZE  # name_offset is the last field of a function entry

# The engine passes arguments by position; param_count counts every parameter
POSITIONAL_KINDS = (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)


@dataclass
class LabelSite:
    """A placed label, or an operand referring to one: the label's name, the position in the code buffer, the
    function it is in and, for an operand while check_compiled is on, where its opcode was emitted"""
    name: str
    offset: int
    function_name: str
    source_site: SourceSite | None = None


@dataclass
class PooledString:
    """String-pool entry; xref_offsets are final file offsets patched by _write_string_pool()"""
    text: str
    section: StringPoolSection
    xref_offsets: list[int] = field(default_factory = list)


@dataclass
class DebugArg:
    type: ScpFunctionCallDebugInfoArg.Type
    value: ScpValue
    string: PooledString | None = None  # set when value is a pooled string


@dataclass
class DebugRecord:
    call_type: ScpFunctionCallDebugInfo.CallType
    func_id: int
    args: list[DebugArg]


@dataclass
class ScpFunction:
    """A registered script function pending compilation, plus its pending table entry"""
    index: int
    name: str
    body: Callable
    original_body: Callable  # the body before any hook replaced it
    signature: inspect.Signature
    entry: ScpFunctionEntry
    debug_argc: dict[str, int] = field(default_factory = dict)       # CALL return label -> args passed explicitly
    calls: list[TrackedCall] = field(default_factory = list)
    debug_records: list[DebugRecord] = field(default_factory = list)
    callback_bodies: list[Callable] = field(default_factory = list)  # from function callbacks, in chain order; may repeat or include the original


class ScpWriter:
    """Compiles the opcode calls of an executed DSL script into a .dat"""

    # Byte-exact round trip with the original compiler: a never-deduplicated string pool in section order and
    # call-site debug-info records. Neither is believed to change behavior in-game.
    round_trip = True

    # Check that the compiled bytes decompile again (disassemble and lift), with errors pointing at script lines
    check_compiled = True

    def __init__(self):
        # The script and what it registers
        self.dat_name: str = None                            # the .dat create_scp_writer() names; None before it
        self.functions: list[ScpFunction] = []               # in registration order, which is code order
        self.functions_by_name: dict[str, ScpFunction] = {}
        self.global_vars: list[ScpGlobalVar] = []
        self.global_var_indices: dict[str, int] = {}
        self.global_vars_block: Callable | None = None       # the @GlobalVars() function that declared the table
        self.in_global_vars_body: bool = False               # GLOBAL_VAR is allowed while that body runs

        # The compile: build() sets these as it runs
        self.globals: dict | None = None                     # the script's globals, once the compile starts
        self.registration_closed: bool = False               # the header is counted: no function or hook may register
        self.function_table: list[ScpFunction] = []          # sorted by name bytes, as on disk
        self.fs: fileio.FileStream = None                    # the code buffer, then the .dat being written (in memory)
        self.code_offset: int = None                         # file offset of the code buffer
        self.current_function: ScpFunction = None            # the function compiling; None outside a body
        self.call_tracker: CallDebugInfoTracker = None       # round_trip only: the body's calls for the debug records

        # Labels and strings
        self.labels: dict[str, LabelSite] = {}
        self.label_refs: list[LabelSite] = []
        self.strings: list[PooledString] = []
        self.strings_by_text: dict[str, PooledString] = {}
        self.code_string_xrefs: list[tuple[PooledString, int]] = []

        # The compile check's source map
        self.source_map: dict[int, SourceSite | None] = {}   # code position -> where it was emitted
        self.current_site: SourceSite | None = None          # the compiling opcode's site, for its label operand
        # id(), not the code: code objects hash their constants on every lookup and compare equal across files
        self.opcode_emitter_code_ids: set[int] = set()       # code of every opcode emitter and of what it wraps

        # Hooks
        self.hooks: HookRegistry = HookRegistry(self)

    def init(self, name: str):
        self.dat_name = name

    @property
    def compile_started(self) -> bool:
        """build() has begun: the script's globals are set"""
        return self.globals is not None

    # Script registration: functions, common imports, global vars and replaced bodies

    def LLILCode(self, debug_argc: dict[str, int] | None = None):
        def wrapper(func):
            self._register_function(func, debug_argc = debug_argc)
            return func

        return wrapper

    def LLILCommonCode(self, debug_argc: dict[str, int] | None = None):
        def wrapper(func):
            self._register_function(func, is_common_func = True, debug_argc = debug_argc)
            return func

        return wrapper

    def CommonImports(self):
        """Declares which common functions this script bakes into its bytecode: some imported from
        the shared library, some defined locally as a fallback when this script's own copy diverges
        from the library's canonical body. Like GlobalVars, the decorated body runs immediately - it
        returns the functions to register, in this script's own code order, and each one is
        registered the same way an inline @scena.LLILCommonCode() definition would be. debug_argc
        isn't exposed here because it can never apply: it's only recovered when round_trip is True
        (pair_call_debug_info), but the manifest is only emitted when round_trip is False - the two
        conditions can't hold at once.
        """
        def wrapper(func):
            for common_func in func():
                self._register_function(common_func, is_common_func = True)

            return func

        return wrapper

    def GlobalVars(self):
        """Declares the script's global variable table, once, in table order (declaration order == on-disk index). A
        hook adds globals with GLOBAL_VAR in a run callback, after the script's, so their indices stay.

        Unlike LLILCode/LLILCommonCode, the decorated body runs immediately - the table must exist before
        _compile_functions() runs, since LOAD_GLOBAL/SET_GLOBAL resolve names against it at compile time.
        """
        def wrapper(func):
            require_function(func, 'GlobalVars')
            if self.dat_name is None:
                raise ValueError(f'{def_location(func)}: @GlobalVars() runs before create_scp_writer(); '
                                 'a hook adds global vars with GLOBAL_VAR in a run callback')

            if self.global_vars_block is not None:
                raise ValueError(f'{def_location(func)}: the global var table is already declared at '
                                 f'{def_location(self.global_vars_block)}')

            self.global_vars_block = func
            self.in_global_vars_body = True
            try:
                func()

            finally:
                self.in_global_vars_body = False

            return func

        return wrapper

    def add_global_var(self, name: str, type: int):
        # The header counts the globals before any body compiles
        if self.current_function is not None:
            raise ValueError(f'{self.current_function.name}: GLOBAL_VAR({name!r}) is inside a function body; '
                             'declare it in @scena.GlobalVars()')

        # Once the compile has started, run and function callbacks may add globals
        if not self.in_global_vars_body and not self.compile_started:
            raise ValueError(f"GLOBAL_VAR({name!r}) is outside @scena.GlobalVars() and a hook's run or function callback")

        if name in self.global_var_indices:
            raise ValueError(f'global var already declared: {name!r}')

        self.global_var_indices[name] = len(self.global_vars)
        self.global_vars.append(ScpGlobalVar(name, type))

    def global_var_index(self, name: str) -> int:
        index = self.global_var_indices.get(name)
        if index is None:
            raise ValueError(f'unknown global var {name!r}; declared: {sorted(self.global_var_indices)}')

        return index

    def _register_function(self, func: Callable, is_common_func: bool = False,
                           debug_argc: dict[str, int] | None = None):
        """A script function: checked, then given its pending table entry (registration order is code order)"""
        require_function(func, 'LLILCommonCode' if is_common_func else 'LLILCode')
        self._require_open(func)
        name = func.__name__
        if name in self.functions_by_name:
            raise ValueError(f'{def_location(func)}: duplicate function name: {name!r}')

        signature = self._signature(func, name)
        self._check_parameters(func, name, signature)

        entry = self._new_function_entry(name, len(signature.parameters), is_common_func)
        f = ScpFunction(index = UNRESOLVED_FUNC_INDEX, name = name, body = func, original_body = func,
                        signature = signature, entry = entry, debug_argc = debug_argc or {})
        self.functions.append(f)
        self.functions_by_name[name] = f

    @classmethod
    def _new_function_entry(cls, name: str, param_count: int, is_common_func: bool) -> ScpFunctionEntry:
        entry = ScpFunctionEntry()
        entry.offset                = UNRESOLVED_FUNC_OFFSET
        entry.param_count           = param_count
        entry.is_common_func        = int(is_common_func)
        entry.byte06                = 0  # meaning unknown; the parser rejects any other value
        entry.default_params_count  = 0  # placeholder - overwritten by _write_default_params()
        entry.default_params_offset = 0  # placeholder - overwritten by _write_default_params()
        entry.param_flags_offset    = 0  # placeholder - overwritten by _write_param_flags()
        entry.debug_info_count      = 0  # placeholder - overwritten by _write_debug_records()
        entry.debug_info_offset     = 0  # placeholder - overwritten by _write_debug_records()
        entry.name_hash             = hash_func_Name(name)
        entry.name_offset           = 0  # stays 0 in memory: _write_string_pool() patches the file's table directly
        return entry

    def _require_open(self, func: Callable):
        """Functions and hooks register before the header counts them: in the script, at hook import time or in a run
        callback - never from a body while it compiles"""
        if self.registration_closed:
            raise ValueError(f'{def_location(func)}: {func.__name__} is registered while the script compiles; '
                             'register functions and hooks at hook import time or in a run callback')

    @classmethod
    def _signature(cls, func: Callable, name: str) -> inspect.Signature:
        """func's signature with its annotations evaluated (under `from __future__ import annotations` they are
        strings); a misspelled type is an error at its def"""
        try:
            return inspect.signature(func, eval_str = True)

        except (NameError, AttributeError, SyntaxError) as e:
            raise TypeError(f'{def_location(func)}: {name}: {e}') from e

    @classmethod
    def _check_parameters(cls, func: Callable, name: str, signature: inspect.Signature):
        """Every parameter is positional, has a type and a default of that type the .dat can store, else a TypeError
        at func's def (instead of one without a location while the body compiles or from _write_default_params /
        _write_param_flags)"""
        for param in signature.parameters.values():
            try:
                if param.kind not in POSITIONAL_KINDS:
                    raise TypeError('must be positional (no *args, keyword-only or **kwargs)')

                if param.annotation is param.empty or param.annotation is None:
                    raise TypeError('needs a type: Value32, Nullable32, str, NullableStr or Pointer')

                flags = ScpParamFlags(typ = param.annotation)
                if param.default is None:
                    raise TypeError('a default is an int, float or str, not None')

                if param.default is not param.empty:
                    value = ScpValue(param.default)
                    is_string = value.type == ScpValue.Type.String
                    if is_string != flags.takes_string():
                        raise TypeError(f"a {flags.get_python_type()} parameter can't default to {param.default!r}")

                    if not is_string:
                        cls._value_bytes(value)

            except (NotImplementedError, TypeError, ValueError) as e:
                raise TypeError(f'{def_location(func)}: parameter {param.name} of {name}: {e}') from e

    @classmethod
    def _replace_body(cls, f: ScpFunction, body: Callable):
        """f keeps its position, table index, common flag and name hash; its signature merges with the replacement's"""
        f.signature = cls._replaced_signature(f, body)
        f.body = body
        f.debug_argc = {}  # keyed by the original's return labels, which a replacement may reuse for other calls

    @classmethod
    def _replaced_signature(cls, f: ScpFunction, body: Callable) -> inspect.Signature:
        """The replacement's signature, with the original's annotation or default wherever it gives none: a default can
        change but never go (the engine may call the function by name without that argument)"""
        signature = cls._signature(body, f.name)
        params = list(signature.parameters.values())
        others = [param.name for param in params if param.kind not in POSITIONAL_KINDS]
        if others:
            raise TypeError(f"{def_location(body)}: {f.name}'s replacement can't take *args, keyword-only or **kwargs "
                            f"parameters ({', '.join(others)}); a wrapper keeps the replaced signature with functools.wraps")

        if len(params) != f.entry.param_count:
            raise TypeError(f'{def_location(body)}: {f.name} takes {f.entry.param_count} parameters, '
                            f'its replacement {len(params)}')

        merged = [param.replace(annotation = original.annotation if param.annotation is param.empty else param.annotation,
                                default = original.default if param.default is param.empty else param.default)
                  for param, original in zip(params, f.signature.parameters.values())]
        merged_signature = signature.replace(parameters = merged)
        cls._check_parameters(body, f.name, merged_signature)
        return merged_signature

    # The compile: run() and build()

    def run(self, g: dict):
        """Compile the script and write the .dat - only once compiling succeeded, so a failure leaves an older .dat as it was"""
        data = self.build(g)
        Path(self.dat_name).write_bytes(data)

    def build(self, g: dict) -> bytes:
        """Compile every registered function into the script's bytes, in memory; with check_compiled, the bytes must
        decompile again. A failure ends the compile like any other: one compile per writer"""
        self.globals = g  # compile_started: from here on add_function registers at once, GLOBAL_VAR and _inject work
        self.hooks._start(g)

        # Counted after the hooks, which may add functions and globals; nothing registers from here on
        self.registration_closed = True
        hdr = ScpHeader()
        hdr.function_count = len(self.functions)
        hdr.global_var_count = len(self.global_vars)

        self._build_function_table()
        code = self._compile_functions()
        self._build_debug_records()

        data, code_end = self._write_file(hdr, code)
        if self.check_compiled:
            functions = [CheckedFunction(f.name, f.entry.offset, f.body) for f in self.functions]
            CompileCheck(self.dat_name, functions, self.source_map, self.code_offset).run(data, code_end)

        return data

    # build()'s steps and their helpers

    def _build_function_table(self):
        """Sort the table by name bytes like the original compiler; CALL operands and PUSH_CURRENT_FUNC_ID use this index"""
        encoding = default_encoding()
        self.function_table = sorted(self.functions, key = lambda f: f.name.encode(encoding))

        for index, f in enumerate(self.function_table):
            f.index = index
            name = self._add_string(f.name, StringPoolSection.Name)
            name.xref_offsets.append(ScpHeader.SIZE + index * ScpFunctionEntry.SIZE + NAME_OFFSET_FIELD_OFFSET)

    def _compile_functions(self) -> fileio.FileStream:
        """Compile every function in script (source) order into a memory buffer; offsets are relative until _relocate_code()"""
        code = fileio.FileStream(encoding = default_encoding()).OpenMemory()
        self.fs = code
        self.opcode_emitter_code_ids = {id(emitter_code) for emitter_code in self._opcode_emitter_codes()}

        try:
            for f in self.functions:
                self.current_function = f
                self.call_tracker = CallDebugInfoTracker(get_param_count = self._get_param_count) if self.round_trip else None
                f.entry.offset = code.Position
                log.debug(f'{f.name} @ code+0x{f.entry.offset:08X}')
                self._run_body(f, f.body)

                if self.call_tracker is not None:
                    f.calls = self.call_tracker.ordered_calls()

        finally:
            # Also after a failed body: no statement compiles outside one
            self.current_function = None
            self.call_tracker = None

        return code

    @classmethod
    def _run_body(cls, f: ScpFunction, body: Callable):
        """Emit a body's opcodes; an LLIL body reads its arguments from the VM stack, not from its parameters"""
        body(*[None] * f.entry.param_count)

    def _opcode_emitters(self):
        """The functions the compile runs to emit opcodes: each function's original body and every body its function
        callbacks returned (f.body is one of them), and each opcode callback"""
        for f in self.functions:
            yield f.original_body
            yield from f.callback_bodies

        yield from self.hooks.opcode_callbacks

    def _opcode_emitter_codes(self):
        """The code of every opcode emitter and of the functions it wraps"""
        for emitter in self._opcode_emitters():
            for layer in wrapped_chain(emitter):
                code = getattr(layer, '__code__', None)
                if code is not None:
                    yield code

    def _get_param_count(self, func: Callable) -> int:
        return self._find_function(func).entry.param_count

    def _build_debug_records(self):
        """Turn tracked call sites into debug-info records, in table order like the original compiler"""
        if not self.round_trip:
            return

        for f in self.function_table:
            f.debug_records = [self._debug_record(f, call) for call in f.calls]

    def _debug_record(self, f: ScpFunction, call: TrackedCall) -> DebugRecord:
        args = [self._debug_arg(value) for value in call.args]
        if call.call_type == ScpFunctionCallDebugInfo.CallType.Local:
            return self._local_call_record(f, call, args)

        if call.call_type == ScpFunctionCallDebugInfo.CallType.Syscall:
            return self._syscall_record(call, args)

        return self._script_call_record(call, args)  # Script and ScriptNoReturn

    def _debug_arg(self, value: TrackedValue) -> DebugArg:
        if value.type == ScpFunctionCallDebugInfoArg.Type.Constant:
            scp_value, string = value.payload
            return DebugArg(value.type, scp_value, string)

        return DebugArg(value.type, ScpValue(ScpFunctionCallDebugInfoArg.NON_CONSTANT_VALUE))

    def _local_call_record(self, f: ScpFunction, call: TrackedCall, args: list[DebugArg]) -> DebugRecord:
        """The callee by table index; only the arguments passed explicitly (debug_argc, by the call's return label)"""
        func_id = self._find_function(call.target).index
        args = args[:f.debug_argc.get(call.ret_label, len(args))]
        return DebugRecord(call_type = call.call_type, func_id = func_id, args = args)

    @classmethod
    def _syscall_record(cls, call: TrackedCall, args: list[DebugArg]) -> DebugRecord:
        """No callee id; the subsystem and the command lead the arguments"""
        args = [DebugArg(ScpFunctionCallDebugInfoArg.Type.Constant, ScpValue(value)) for value in call.target] + args
        return DebugRecord(call_type = call.call_type, func_id = ScpFunctionCallDebugInfo.NO_FUNC_ID, args = args)

    def _script_call_record(self, call: TrackedCall, args: list[DebugArg]) -> DebugRecord:
        """No callee id; the pooled 'module.func' name leads the arguments"""
        module, func = (value.value if isinstance(value, ScpValue) else value for value in call.target)
        name = self._add_string(f'{module}.{func}', StringPoolSection.Debug)
        args = [DebugArg(ScpFunctionCallDebugInfoArg.Type.Constant, ScpValue(name.text), name)] + args
        return DebugRecord(call_type = call.call_type, func_id = ScpFunctionCallDebugInfo.NO_FUNC_ID, args = args)

    def _write_file(self, hdr: ScpHeader, code: fileio.FileStream) -> tuple[bytes, int]:
        """Lay the .dat out in memory around the compiled code - header, function table, default params, param flags,
        debug records, global vars, code, string pool - and return its bytes and where its code ends"""
        self.fs = fileio.FileStream(encoding = default_encoding()).OpenMemory()
        self.fs.Write(hdr.to_bytes())  # rewritten once global_var_offset is known

        self._write_function_table()  # reserves its space; rewritten below once every offset is known
        self._write_default_params()
        self._write_param_flags()
        self._write_debug_records()

        hdr.global_var_offset = self.fs.Position  # end of debug args, start of the global var table
        self._write_global_vars()

        self.code_offset = self.fs.Position  # the code follows the global var table
        self._relocate_code(code, self.code_offset)
        self.fs.Write(code)
        code_end = self.fs.Position

        with self.fs.PositionSaver:
            self._write_function_table()

        self._write_string_pool()

        self.fs.Position = 0
        self.fs.Write(hdr.to_bytes())
        return self.fs.ReadAll(), code_end

    def _write_function_table(self):
        """The function entries, right after the header (written twice: placeholders, then the real ones)"""
        self.fs.Position = ScpHeader.SIZE
        for f in self.function_table:
            self.fs.Write(f.entry.to_bytes())

    def _write_default_params(self):
        """Each function's defaults, in table order: its trailing defaulted parameters, in parameter order"""
        for f in self.function_table:
            defaults = [param.default for param in f.signature.parameters.values() if param.default is not param.empty]
            f.entry.default_params_offset = self.fs.Position
            f.entry.default_params_count = len(defaults)

            for default in defaults:
                self._write_scp_value(ScpValue(default), StringPoolSection.Default)  # checked at the def

    def _write_param_flags(self):
        for f in self.function_table:
            f.entry.param_flags_offset = self.fs.Position

            for param in f.signature.parameters.values():
                self.fs.Write(ScpParamFlags(typ = param.annotation).to_bytes())

    def _write_debug_records(self):
        records = [record for f in self.function_table for record in f.debug_records]
        info_offset = self.fs.Position + len(records) * ScpFunctionCallDebugInfo.SIZE

        for f in self.function_table:
            f.entry.debug_info_offset = self.fs.Position
            f.entry.debug_info_count = len(f.debug_records)

            for record in f.debug_records:
                info = ScpFunctionCallDebugInfo()
                info.func_id = record.func_id
                info.call_type = record.call_type
                info.arg_count = len(record.args)
                info.info_offset = info_offset
                self.fs.Write(info.to_bytes())

                info_offset += info.arg_count * ScpFunctionCallDebugInfoArg.SIZE

        for record in records:
            for arg in record.args:
                if arg.string is not None:
                    arg.string.xref_offsets.append(self.fs.Position)
                    self.fs.WriteULong(UNRESOLVED_STRING_OFFSET)

                else:
                    self.fs.Write(arg.value.to_bytes())

                self.fs.WriteULong(arg.type)

    def _write_global_vars(self):
        for var in self.global_vars:
            self._write_string_ref(var.name, StringPoolSection.Global)
            self.fs.WriteULong(var.type)

    def _relocate_code(self, code: fileio.FileStream, code_offset: int):
        """Move every position recorded while compiling into the code buffer to its final file offset, and patch each
        label operand with its label's file offset"""
        for f in self.functions:
            f.entry.offset += code_offset

        with code.PositionSaver:
            for ref in self.label_refs:
                label = self.labels.get(ref.name)
                if label is None:
                    raise ValueError(f'{location_prefix(ref.source_site)}{ref.function_name}: '
                                     f'undefined label {ref.name!r}')

                if label.function_name != ref.function_name:
                    log.warning(f'{location_prefix(ref.source_site)}{ref.function_name}: '
                                f'jumps to label {ref.name!r} in {label.function_name} (another function)')

                code.Position = ref.offset
                code.WriteULong(label.offset + code_offset)

        for string, offset in self.code_string_xrefs:
            string.xref_offsets.append(offset + code_offset)

    def _write_string_pool(self):
        strings = sorted(self.strings, key = lambda string: string.section) if self.round_trip else self.strings

        for string in strings:
            offset = self.fs.Position
            self.fs.Write(str_to_bytes(string.text))

            with self.fs.PositionSaver:
                for xref_offset in string.xref_offsets:
                    self.fs.Position = xref_offset
                    self.fs.WriteULong(offset | STRING_OFFSET_TAG)

    # Opcode emission: operands, labels and strings

    def handle_opcode(self, opcode: int, *args):
        """Write one opcode a DSL opcode function emitted, unless an opcode callback drops it"""
        if self.current_function is None:
            raise ValueError(f'{ED9Opcode(opcode).name} is outside a function body')

        site = self._opcode_site() if self.check_compiled else None
        if self.hooks._dropped_by_opcode_callbacks(opcode, args, site):
            return

        # Before this opcode is written: source_map is keyed by its start offset; a label operand reads current_site
        if self.check_compiled:
            self.current_site = site
            self.source_map[self.fs.Position] = site

        # bool is an int subclass, so the opcode functions' isinstance asserts accept True/False
        for arg in args:
            if isinstance(arg, bool):
                raise TypeError(f'{ED9Opcode(opcode).name} takes no bool operand: {arg!r}')

        # The value's Python type picks its encoding, so PUSH_FLOAT(1) would push an Integer
        if opcode == ED9Opcode.PUSH_FLOAT:
            args = (float(args[0]),)

        payload = None
        if opcode in PUSH_CONSTANT_OPS:
            payload = self._emit_push_constant(args[0])

        elif opcode == ED9Opcode.PUSH_CURRENT_FUNC_ID:
            self._write_push_value(ScpValue(RawInt(self.current_function.index)))

        elif opcode == ED9Opcode.PUSH_RET_ADDR:
            self._write_push_header()
            self._write_label_ref(args[0])

        elif opcode == ED9Opcode.UNKNOWN_28:
            # No descriptor - the operand format is unknown, so the operand bytes are written as given
            self.fs.WriteByte(opcode)
            self.fs.Write(args[0])

        else:
            self._emit_described_opcode(opcode, args)

        if self.call_tracker is not None:
            self.call_tracker.on_opcode(opcode, args, payload)

    def _opcode_site(self) -> SourceSite | None:
        """Where the opcode being compiled was emitted: the innermost frame running an opcode emitter or a function it
        wraps (a helper either called counts as its call). f_lasti, not f_lineno: f_lineno scans the line table,
        which grows with the function"""
        frame = sys._getframe(1)
        while frame is not None and id(frame.f_code) not in self.opcode_emitter_code_ids:
            frame = frame.f_back

        return SourceSite(frame.f_code, frame.f_lasti, self.hooks.trigger_site) if frame is not None else None

    def _emit_push_constant(self, operand: int | float | str | RawInt) -> tuple[ScpValue, PooledString | None]:
        """PUSH and its constant pseudo-ops (PUSH_CONSTANT_OPS) all collapse to the on-disk PUSH opcode + size byte +
        ScpValue; returns the tracker's (value, string) payload"""
        value = ScpValue(operand)
        return value, self._write_push_value(value)

    def _emit_described_opcode(self, opcode: int, args: tuple):
        descriptor = ED9_INSTRUCTION_TABLE.get_descriptor(opcode)
        operand_descriptors = OperandDescriptor.from_format_string(descriptor.operand_fmt, ED9_FORMAT_TABLE)

        assert len(operand_descriptors) == len(args), \
            f'{descriptor.mnemonic}: expected {len(operand_descriptors)} operands, got {len(args)}'

        self.fs.WriteByte(opcode)

        for op_desc, value in zip(operand_descriptors, args):
            self._write_operand(op_desc, value)

    def _write_push_value(self, value: ScpValue) -> PooledString | None:
        self._write_push_header()
        return self._write_scp_value(value)

    def _write_push_header(self):
        """Real on-disk PUSH opcode + size/type byte, shared by every PUSH-family value"""
        self.fs.WriteByte(ED9Opcode.PUSH)
        self.fs.WriteByte(PUSH_SIZE_BYTE)

    def _write_scp_value(self, value: ScpValue, section: StringPoolSection = StringPoolSection.Code) -> PooledString | None:
        """Write a ScpValue's on-disk bytes, deferring String-typed values through the string pool"""
        if value.type == ScpValue.Type.String:
            return self._write_string_ref(value.value, section)

        self.fs.Write(self._value_bytes(value))
        return None

    @classmethod
    def _value_bytes(cls, value: ScpValue) -> bytes:
        """A non-string value's on-disk word; ValueError for one the game can't use (checked here, not in ScpValue,
        which must still decode and re-encode any word)"""
        if value.type == ScpValue.Type.Float:
            if not math.isfinite(value.value):
                raise ValueError(f"non-finite float {value.value}: the game can't use it")

            if ScpValue.float_word(value.value) is None:
                raise ValueError(f"float {value.value} is outside float32's range: the game can't use it")

        return value.to_bytes()

    def _write_operand(self, op_desc: OperandDescriptor, value):
        writers = {
            OperandType.SInt8        : self.fs.WriteChar,
            OperandType.UInt8        : self.fs.WriteByte,
            OperandType.SInt16       : self.fs.WriteShort,
            OperandType.UInt16       : self.fs.WriteUShort,
            OperandType.SInt32       : self.fs.WriteLong,
            OperandType.UInt32       : self.fs.WriteULong,
            OperandType.Float32      : self.fs.WriteFloat,
            OperandType.Offset       : self._write_label_ref,
            ED9OperandType.Func      : self._write_func_operand,
            ED9OperandType.Value     : self._write_value_operand,
            ED9OperandType.GlobalVar : self.fs.WriteLong,
        }

        writers[op_desc.type](value)

    def _write_value_operand(self, value):
        self._write_scp_value(value if isinstance(value, ScpValue) else ScpValue(value))

    def _write_func_operand(self, value):
        self.fs.WriteUShort(self._find_function(value).index)

    def _find_function(self, func: Callable) -> ScpFunction:
        f = self.functions_by_name.get(func.__name__)
        if f is None:
            raise TypeError(f'CALL has unknown function name: {func.__name__}')

        return f

    def add_label(self, name: str):
        """Labels are file-wide: a name is defined once in the script"""
        f = self.current_function
        if f is None:
            raise ValueError(f'label({name!r}) is outside a function body')

        placed = self.labels.get(name)
        if placed is not None:
            raise ValueError(f'{f.name}: label {name!r} is already defined in {placed.function_name}')

        self.labels[name] = LabelSite(name = name, offset = self.fs.Position, function_name = f.name)

    def _write_label_ref(self, name: str):
        """Record the operand, then write a placeholder that _relocate_code() patches"""
        self.label_refs.append(LabelSite(name = name, offset = self.fs.Position,
                                         function_name = self.current_function.name, source_site = self.current_site))
        self.fs.WriteULong(UNRESOLVED_LABEL_OFFSET)

    def _write_string_ref(self, text: str, section: StringPoolSection) -> PooledString:
        """Write a placeholder tagged string reference at the current position"""
        string = self._add_string(text, section)

        if section == StringPoolSection.Code:
            self.code_string_xrefs.append((string, self.fs.Position))  # code-relative until _relocate_code()

        else:
            string.xref_offsets.append(self.fs.Position)

        self.fs.WriteULong(UNRESOLVED_STRING_OFFSET)
        return string

    def _add_string(self, text: str, section: StringPoolSection) -> PooledString:
        """String-pool entry for text - the original compiler never deduplicates, so entries are only shared without round_trip"""
        if not self.round_trip and text in self.strings_by_text:
            return self.strings_by_text[text]

        string = PooledString(text = text, section = section)
        self.strings.append(string)
        self.strings_by_text.setdefault(text, string)
        return string


_gScp = ScpWriter()


def create_scp_writer(name: str) -> ScpWriter:
    _gScp.init(name)

    return _gScp


def get_scp_writer() -> ScpWriter:
    return _gScp
