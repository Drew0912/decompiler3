"""Writer runtime for reassembling ED9 VM bytecode from decompiled Python script output"""

import inspect
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import FunctionType
from typing import Callable

from common import fileio

from common.config import default_encoding
from common.logging import log
from ir.llil import WORD_SIZE
from ..disasm import ED9_INSTRUCTION_TABLE, ED9Opcode, ED9OperandType, ED9_FORMAT_TABLE, Instruction, OperandDescriptor, OperandType
from ..parser.crc32 import hash_func_Name
from ..parser.scp import CallDebugInfoTracker, ScpFunctionError, TrackedCall, TrackedValue, PUSH_CONSTANT_OPS
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
from .scp_compile_check import CompileCheckError, SourceSite, def_location, location_prefix, require_decompilable

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
    """An LLILCode()-decorated function pending compilation, plus its pending table entry"""
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


class _OriginalFunction:
    """What original.Name returns. Not a plain function, so it can't become a replacement or a callback (the script's
    names would be set in this module)"""

    def __init__(self, writer: 'ScpWriter', f: ScpFunction):
        self.writer = writer
        self.function = f
        self.__name__ = f.name  # CALL(original.Name) finds the function by name, like CALL(Name)

    @property
    def __signature__(self) -> inspect.Signature:
        """The original's, so a functools.wraps wrapper of original.Name keeps it"""
        return self.writer._signature(self.function.original_body, self.function.name)

    def __call__(self, *args, **kwargs):
        """Bound like a call to the original, never read (see _run_body)"""
        f = self.function
        if self.writer.current_function is None:
            raise ValueError(f'original.{f.name}() is outside a function body')

        signature = self.__signature__
        try:
            signature.bind(*args, **kwargs)

        except TypeError as e:
            raise TypeError(f'original.{f.name}(): {e}') from e

        self.writer._run_body(f, f.original_body)

    def __repr__(self) -> str:
        return f'original.{self.__name__}'


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
        self.source_map: dict[int, SourceSite] = {}          # code position -> where it was emitted
        self.current_site: SourceSite | None = None          # the compiling opcode's site, for its label operand
        # id(), not the code: code objects hash their constants on every lookup and compare equal across files
        self.opcode_emitter_code_ids: set[int] = set()       # code of every opcode emitter and of what it wraps

        # Hooks
        self.func_callbacks: list[Callable] = []             # cb(name, func) -> None or a new body
        self.replaced: dict[str, Callable] = {}              # replace_function name -> its body
        self.hook_functions: list[Callable] = []             # the hooks' own functions, never the writer's
        self.run_callbacks: list[Callable] = []              # cb(g) when the compile starts
        self.opcode_callbacks: list[Callable] = []           # cb(opcode, *args) -> True drops it
        self.in_opcode_callback: bool = False                # opcodes a callback emits skip the callbacks
        self.trigger_site: SourceSite | None = None          # the triggering opcode's site while callbacks run
        self.added_functions: list[Callable] = []            # add_function, registered when the compile starts
        self.injected_modules: set[int] = set()              # id() of every hook module given the script's names

    def init(self, name: str):
        self.dat_name = name

    @property
    def compile_started(self) -> bool:
        """build() has begun: the script's globals are set"""
        return self.globals is not None

    # Script registration: functions, common imports and global vars

    def _function_decorator(self, is_common_func: bool, debug_argc: dict[str, int] | None):
        def wrapper(func):
            self._require_function(func, 'LLILCommonCode' if is_common_func else 'LLILCode')
            name = func.__name__
            self._require_open(func)
            if name in self.functions_by_name:
                raise ValueError(f'{def_location(func)}: duplicate function name: {name!r}')

            signature = self._signature(func, name)
            self._check_parameters(func, name, signature)

            entry = ScpFunctionEntry()
            entry.offset                = UNRESOLVED_FUNC_OFFSET
            entry.param_count           = len(signature.parameters)
            entry.is_common_func        = int(is_common_func)
            entry.byte06                = 0  # unknown meaning, not worrying about it per user
            entry.default_params_count  = 0  # placeholder - overwritten by _write_default_params()
            entry.default_params_offset = 0  # placeholder - overwritten by _write_default_params()
            entry.param_flags_offset    = 0  # placeholder - overwritten by _write_param_flags()
            entry.debug_info_count      = 0  # placeholder - overwritten by _write_debug_records()
            entry.debug_info_offset     = 0  # placeholder - overwritten by _write_debug_records()
            entry.name_hash             = hash_func_Name(name)
            entry.name_offset           = 0  # stays 0 in memory: _write_string_pool() patches the file's table directly

            f = ScpFunction(index = UNRESOLVED_FUNC_INDEX, name = name, body = func, original_body = func,
                            signature = signature, entry = entry, debug_argc = debug_argc or {})
            self.functions.append(f)
            self.functions_by_name[name] = f

            return func

        return wrapper

    def LLILCode(self, debug_argc: dict[str, int] | None = None):
        return self._function_decorator(is_common_func = False, debug_argc = debug_argc)

    def LLILCommonCode(self, debug_argc: dict[str, int] | None = None):
        return self._function_decorator(is_common_func = True, debug_argc = debug_argc)

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
            register = self.LLILCommonCode()
            for common_func in func():
                register(common_func)

            return func

        return wrapper

    def GlobalVars(self):
        """Declares the script's global variable table, once, in table order (declaration order == on-disk index). A
        hook adds globals with GLOBAL_VAR in a run callback, after the script's, so their indices stay.

        Unlike LLILCode/LLILCommonCode, the decorated body runs immediately - the table must exist before
        _compile_functions() runs, since LOAD_GLOBAL/SET_GLOBAL resolve names against it at compile time.
        """
        def wrapper(func):
            self._require_function(func, 'GlobalVars')
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

    # Hooks: the hook-file API and how build() applies it

    def registerFuncCallback(self, cb: Callable) -> Callable:
        """See scp_writer_hooks.registerFuncCallback"""
        self._add_hook_function(cb, 'registerFuncCallback')
        self.func_callbacks.append(cb)
        return cb

    def replace_function(self, name: str):
        """See scp_writer_hooks.replace_function"""
        if not isinstance(name, str):
            raise TypeError(f"replace_function takes the function's name - @replace_function('Name') - not {name!r}")

        def wrapper(body):
            self._add_hook_function(body, f'replace_function({name!r})')
            earlier = self.replaced.get(name)
            if earlier is not None:
                log.warning(f'{def_location(body)}: replace_function({name!r}) again, '
                            f'overriding the one at {def_location(earlier)}')

            self.replaced[name] = body
            self.func_callbacks.append(lambda func_name, func: body if func_name == name else None)
            return body

        return wrapper

    def registerRunCallback(self, cb: Callable) -> Callable:
        """See scp_writer_hooks.registerRunCallback"""
        self._add_hook_function(cb, 'registerRunCallback')
        self.run_callbacks.append(cb)
        return cb

    def registerOpcodeCallback(self, cb: Callable) -> Callable:
        """See scp_writer_hooks.registerOpcodeCallback"""
        self._add_hook_function(cb, 'registerOpcodeCallback')
        self.opcode_callbacks.append(cb)
        return cb

    def add_function(self, func: Callable) -> Callable:
        """See scp_writer_hooks.add_function"""
        self._add_hook_function(func, 'add_function (used bare: @add_function)')
        if self.compile_started:
            self._register_added(func)

        else:
            self.added_functions.append(func)

        return func

    def _register_added(self, func: Callable):
        """An added function joins the script's after its own functions, so their code stays where it was"""
        existing = self.functions_by_name.get(func.__name__)
        if existing is not None:
            raise ValueError(f'{def_location(func)}: add_function: {func.__name__!r} is already defined at '
                             f'{def_location(existing.original_body)}; replace_function replaces a function')

        self.LLILCode()(func)

    def _add_hook_function(self, func: Callable, what: str):
        """A hook's own function, a plain one (what names it in the error): given the script's names now if the
        compile has started, else when it starts"""
        self._require_function(func, what)
        self._require_open(func)
        self.hook_functions.append(func)
        self._inject(func)

    def _inject(self, func: Callable):
        """Hook bodies read like the script: each script name a hook module doesn't define is set in it, once per module
        - in the modules of the functions func wraps too (a decorator from another module wraps a hook's body)"""
        if not self.compile_started:
            return

        for layer in self._wrapped_chain(func):
            module = getattr(layer, '__globals__', None)
            if module is None or id(module) in self.injected_modules:
                continue

            self.injected_modules.add(id(module))
            for name, value in self.globals.items():
                if not name.startswith('__'):
                    module.setdefault(name, value)

    @classmethod
    def _wrapped_chain(cls, func: Callable):
        """func, then each function it wraps (functools.wraps sets __wrapped__); a cycle ends the chain"""
        seen = set()
        while func is not None and id(func) not in seen:
            seen.add(id(func))
            yield func
            func = getattr(func, '__wrapped__', None)

    def _apply_function_callbacks(self):
        """Run the hook function callbacks over every function and give each replaced one its new body. Its position,
        table index, common flag and name hash stay; its signature merges with the replacement's"""
        for name, body in self.replaced.items():
            if name not in self.functions_by_name:
                raise ValueError(f'{def_location(body)}: replace_function({name!r}): '
                                 f'the script has no function {name!r}')

        for f in self.functions:
            body = f.body
            for cb in self.func_callbacks:
                counts = (len(self.functions), len(self.hook_functions))  # every hook registration grows hook_functions
                replacement = cb(f.name, body)
                if (len(self.functions), len(self.hook_functions)) != counts:
                    raise ValueError(f"{def_location(cb)}: a function callback can't register functions or callbacks")

                if replacement is None:
                    continue

                self._require_function(replacement, f'{def_location(cb)}: {cb.__name__} for {f.name}')
                if replacement is not body:  # a body merely passed on may be the script's or a library's: no names for it
                    self._inject(replacement)

                body = replacement
                f.callback_bodies.append(body)

            if body is not f.body:
                f.signature = self._replaced_signature(f, body)
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

    @classmethod
    def _require_function(cls, obj, what: str):
        """Hooks are plain functions: the source map and the error locations need their code"""
        if not isinstance(obj, FunctionType):
            raise TypeError(f'{what}: expected a plain function (def), not {obj!r}')

    def original_function(self, name: str) -> _OriginalFunction:
        """See scp_writer_hooks.original"""
        if not self.compile_started:
            raise ValueError(f'original.{name} is only available once the compile starts')

        f = self.functions_by_name.get(name)
        if f is None:
            raise AttributeError(f'{Path(self.dat_name).stem} has no function {name!r}')

        return _OriginalFunction(self, f)

    def inline_original_func(self):
        """See scp_writer_hooks.inline_original_func"""
        f = self.current_function
        if f is None:
            raise ValueError('inline_original_func() is outside a function body')

        if f.body is f.original_body:
            raise ValueError(f"{f.name} wasn't replaced; inline_original_func() inlines a replaced function's original body")

        self._run_body(f, f.original_body)

    # The compile: run() and build()

    def run(self, g: dict):
        """Compile the script and write the .dat - only once compiling succeeded, so a failure leaves an older .dat as it was"""
        data = self.build(g)
        Path(self.dat_name).write_bytes(data)

    def build(self, g: dict) -> bytes:
        """Compile every registered function into the script's bytes, in memory; with check_compiled, the bytes must
        decompile again. A failure ends the compile like any other: one compile per writer"""
        self.globals = g
        for func in self.added_functions:
            self._register_added(func)

        for func in self.hook_functions:
            self._inject(func)

        for cb in self.run_callbacks:
            cb(g)

        self._apply_function_callbacks()

        # Counted after the hooks, which may add functions and globals; nothing registers from here on
        self.registration_closed = True
        hdr = ScpHeader()
        hdr.function_count = len(self.functions)
        hdr.global_var_count = len(self.global_vars)

        self._build_function_table()
        code = self._compile_functions()
        self._build_debug_records()

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

        data = self.fs.ReadAll()
        if self.check_compiled:
            self._check_decompilable(data, code_end)

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

        yield from self.opcode_callbacks

    def _opcode_emitter_codes(self):
        """The code of every opcode emitter and of the functions it wraps"""
        for emitter in self._opcode_emitters():
            for layer in self._wrapped_chain(emitter):
                code = getattr(layer, '__code__', None)
                if code is not None:
                    yield code

    def _get_param_count(self, func: Callable) -> int:
        return self._find_function(func).entry.param_count

    def _build_debug_records(self):
        """Turn tracked call sites into debug-info records, in table order like the original compiler"""
        if not self.round_trip:
            return

        ArgType = ScpFunctionCallDebugInfoArg.Type
        CallType = ScpFunctionCallDebugInfo.CallType

        for f in self.function_table:
            for call in f.calls:
                args = [self._debug_arg(value) for value in call.args]

                if call.call_type == CallType.Local:
                    func_id = self._find_function(call.target).index
                    args = args[:f.debug_argc.get(call.ret_label, len(args))]

                elif call.call_type == CallType.Syscall:
                    func_id = ScpFunctionCallDebugInfo.NO_FUNC_ID
                    subsystem, cmd = call.target
                    args = [DebugArg(ArgType.Constant, ScpValue(subsystem)), DebugArg(ArgType.Constant, ScpValue(cmd))] + args

                else:
                    func_id = ScpFunctionCallDebugInfo.NO_FUNC_ID
                    module, func = (value.value if isinstance(value, ScpValue) else value for value in call.target)
                    name = self._add_string(f'{module}.{func}', StringPoolSection.Debug)
                    args = [DebugArg(ArgType.Constant, ScpValue(name.text), name)] + args

                f.debug_records.append(DebugRecord(call_type = call.call_type, func_id = func_id, args = args))

    def _debug_arg(self, value: TrackedValue) -> DebugArg:
        if value.type == ScpFunctionCallDebugInfoArg.Type.Constant:
            scp_value, string = value.payload
            return DebugArg(value.type, scp_value, string)

        return DebugArg(value.type, ScpValue(ScpFunctionCallDebugInfoArg.NON_CONSTANT_VALUE))

    def _write_function_table(self):
        """The function entries, right after the header (build() writes them twice: placeholders, then the real ones)"""
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
        if self.current_function is None:
            raise ValueError(f'{ED9Opcode(opcode).name} is outside a function body')

        site = self._opcode_site() if self.check_compiled else None
        if (self.opcode_callbacks and not self.in_opcode_callback
                and self._dropped_by_opcode_callbacks(opcode, args, site)):
            return

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

        # PUSH and its pseudo-ops all collapse to the on-disk PUSH opcode + size byte + ScpValue
        if opcode in PUSH_CONSTANT_OPS:
            value = ScpValue(args[0])
            string = self._write_push_value(value)
            self._track(opcode, args, (value, string))
            return

        if opcode == ED9Opcode.PUSH_CURRENT_FUNC_ID:
            self._write_push_value(ScpValue(RawInt(self.current_function.index)))
            self._track(opcode, args)
            return

        if opcode == ED9Opcode.PUSH_RET_ADDR:
            self._write_push_header()
            self._write_label_ref(args[0])
            self._track(opcode, args)
            return

        # No descriptor - the operand format is unknown, so the operand bytes are written as given
        if opcode == ED9Opcode.UNKNOWN_28:
            self.fs.WriteByte(opcode)
            self.fs.Write(args[0])
            self._track(opcode, args)
            return

        descriptor = ED9_INSTRUCTION_TABLE.get_descriptor(opcode)
        operand_descriptors = OperandDescriptor.from_format_string(descriptor.operand_fmt, ED9_FORMAT_TABLE)

        assert len(operand_descriptors) == len(args), \
            f'{descriptor.mnemonic}: expected {len(operand_descriptors)} operands, got {len(args)}'

        self.fs.WriteByte(opcode)

        for op_desc, value in zip(operand_descriptors, args):
            self._write_operand(op_desc, value)

        self._track(opcode, args)

    def _dropped_by_opcode_callbacks(self, opcode: int, args: tuple, site: SourceSite | None) -> bool:
        """Run the opcode callbacks, in registration order, on an opcode a body emits; True when one drops it, and the
        rest don't run. The opcodes a callback emits skip the callbacks and carry site as their trigger"""
        self.in_opcode_callback = True
        self.trigger_site = site
        try:
            for cb in self.opcode_callbacks:
                result = cb(opcode, *args)
                if result is True:
                    return True

                if result is not None and result is not False:
                    raise TypeError(f'{def_location(cb)}: opcode callback {cb.__name__} returned {result!r}: '
                                    'True drops the opcode, None or False keeps it')

            return False

        finally:
            self.in_opcode_callback = False
            self.trigger_site = None

    def _opcode_site(self) -> SourceSite | None:
        """Where the opcode being compiled was emitted: the innermost frame running an opcode emitter or a function it
        wraps (a helper either called counts as its call). f_lasti, not f_lineno: f_lineno scans the line table,
        which grows with the function"""
        frame = sys._getframe(1)
        while frame is not None and id(frame.f_code) not in self.opcode_emitter_code_ids:
            frame = frame.f_back

        return SourceSite(frame.f_code, frame.f_lasti, self.trigger_site) if frame is not None else None

    def _track(self, opcode: int, args: tuple, payload = None):
        if self.call_tracker is not None:
            self.call_tracker.on_opcode(opcode, args, payload)

    def _write_push_header(self):
        """Real on-disk PUSH opcode + size/type byte, shared by every PUSH-family value"""
        self.fs.WriteByte(ED9Opcode.PUSH)
        self.fs.WriteByte(PUSH_SIZE_BYTE)

    def _write_push_value(self, value: ScpValue) -> PooledString | None:
        self._write_push_header()
        return self._write_scp_value(value)

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

    def _add_string(self, text: str, section: StringPoolSection) -> PooledString:
        """String-pool entry for text - the original compiler never deduplicates, so entries are only shared without round_trip"""
        if not self.round_trip and text in self.strings_by_text:
            return self.strings_by_text[text]

        string = PooledString(text = text, section = section)
        self.strings.append(string)
        self.strings_by_text.setdefault(text, string)
        return string

    def _write_string_ref(self, text: str, section: StringPoolSection) -> PooledString:
        """Write a placeholder tagged string reference at the current position"""
        string = self._add_string(text, section)

        if section == StringPoolSection.Code:
            self.code_string_xrefs.append((string, self.fs.Position))  # code-relative until _relocate_code()

        else:
            string.xref_offsets.append(self.fs.Position)

        self.fs.WriteULong(UNRESOLVED_STRING_OFFSET)
        return string

    # The compile check: the bytes must decompile again

    def _check_decompilable(self, data: bytes, code_end: int):
        """The compiled bytes disassemble and lift again; a failure names the script line that emitted the failing
        opcode, or the failing function's def. A function that runs on into the next function's code (no RETURN) is a
        warning while the bytes still decompile, and a note on the failure when they don't; the parser's warnings for
        unusual slots get their script line too."""
        try:
            parser, parsed_functions = require_decompilable(data, self.dat_name, code_end)

        except ScpFunctionError as e:
            note = self._run_on_note(e.function, e.runs_on)
            message = f'{self._failure_prefix(e.function, e.offset)}{e}' + (f'; {note}' if note else '')
            raise CompileCheckError(message) from e

        except Exception as e:
            raise CompileCheckError(f'{self.dat_name}: {e}') from e

        runs_on = {parsed_function.name: parsed_function.runs_on for parsed_function in parsed_functions}
        for f in self.functions:
            note = self._run_on_note(f.name, runs_on.get(f.name))
            if note:
                log.warning(note)

        for parsed_function in parsed_functions:
            for inst in parser.get_instructions(parsed_function):
                ref = parsed_function.stack_layout.slot_refs.get(inst.offset)
                if ref is not None and ref.unusual:
                    log.warning(self._failure_text(parsed_function.name, f'addresses {ref}', inst))

    def _run_on_note(self, function_name: str | None, inst: Instruction | None) -> str | None:
        """How the function runs on into the next function's code, located: it has no code at all, or inst runs past
        its end (the parser found it; for an empty function that is the next one's). None when it doesn't"""
        f = self.functions_by_name.get(function_name)
        if f is None:
            return None

        following = self.functions[self.functions.index(f) + 1:]
        if following and following[0].entry.offset == f.entry.offset:
            return self._failure_text(f.name, f'has no code, so it runs on into {following[0].name} without RETURN')

        if inst is not None:
            end = inst.offset + inst.size
            into = next(other.name for other in following if other.entry.offset == end)
            return self._failure_text(f.name, f'runs past its end into {into} without RETURN', inst)

        return None

    def _failure_text(self, function_name: str, message: str, inst: Instruction | None = None) -> str:
        """The failure prefix of inst, else of the function's def, then ScpFunctionError.describe()'s text"""
        offset = inst.offset if inst is not None else None
        return self._failure_prefix(function_name, offset) + ScpFunctionError.describe(function_name, message, inst)

    def _failure_prefix(self, function_name: str | None, offset: int | None) -> str:
        """'file:line: ' of the opcode compiled at a file offset, else of the function's def; '' when neither is known"""
        site = self.source_map.get(offset - self.code_offset) if offset is not None else None
        if site is not None:
            return location_prefix(site)

        f = self.functions_by_name.get(function_name)
        if f is None:
            return ''

        return f'{def_location(f.body)}: '


_gScp = ScpWriter()


def create_scp_writer(name: str) -> ScpWriter:
    _gScp.init(name)

    return _gScp


def get_scp_writer() -> ScpWriter:
    return _gScp
