'''ED9 Format Signatures - Function/syscall signatures for output formatting'''

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import yaml


@dataclass
class ParamHint:
    '''Parameter formatting hint'''
    name: str
    type: Optional[str] = None    # "number", "string", "[string, number]" for union, etc.
    format: Optional[str] = None  # "hex", enum name, etc.
    variadic: bool = False        # True for rest parameters


@dataclass
class ReturnHint:
    '''Return value hint'''
    name: Optional[str] = None
    type: Optional[str] = None
    format: Optional[str] = None


@dataclass
class FunctionSig:
    '''Function signature'''
    params: List[ParamHint] = field(default_factory=list)
    return_hint: Optional[ReturnHint] = None


@dataclass
class SyscallSig:
    '''Syscall signature'''
    name: str
    subsystem: int
    cmd: int
    params: List[ParamHint] = field(default_factory=list)
    return_hint: Optional[ReturnHint] = None


class FormatSignatureDB:
    '''Database of function/syscall signatures for output formatting'''

    def __init__(self):
        self.enums: Dict[str, Dict[int, str]] = {}
        self.functions: Dict[str, FunctionSig] = {}
        self.syscalls: Dict[str, SyscallSig] = {}
        self._syscall_by_id: Dict[Tuple[int, int], SyscallSig] = {}

    def load_yaml(self, path: Path):
        '''Load signatures from YAML file'''
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        if not data:
            return

        self._load_enums(data.get('enums', {}))
        self._load_functions(data.get('functions', {}))
        self._load_syscalls(data.get('syscalls', {}))

    def _load_enums(self, enums_data: Optional[Dict]):
        '''Load enum definitions'''
        if not enums_data:
            return

        for name, values in enums_data.items():
            self.enums[name] = {int(k): v for k, v in values.items()}

    def _load_functions(self, funcs_data: Optional[Dict]):
        '''Load function signatures'''
        if not funcs_data:
            return

        for name, sig_data in funcs_data.items():
            self.functions[name] = self._parse_function_sig(sig_data)

    def _load_syscalls(self, syscalls_data: Optional[Dict]):
        '''Load syscall signatures'''
        if not syscalls_data:
            return

        for name, sig_data in syscalls_data.items():
            sig = self._parse_syscall_sig(name, sig_data)
            self.syscalls[name] = sig
            self._syscall_by_id[(sig.subsystem, sig.cmd)] = sig

    @classmethod
    def _validate_params(cls, params: List[ParamHint], context: str):
        '''Validate parameter list - variadic must be last'''
        for i, p in enumerate(params):
            if p.variadic and i != len(params) - 1:
                raise ValueError(f"{context}: variadic parameter '{p.name}' must be last")

    def _parse_function_sig(self, data: Dict) -> FunctionSig:
        '''Parse function signature from dict'''
        params = [self._parse_param(p) for p in data.get('params', [])]
        self._validate_params(params, 'function')
        return_hint = self._parse_return(data.get('return'))
        return FunctionSig(params=params, return_hint=return_hint)

    def _parse_syscall_sig(self, name: str, data: Dict) -> SyscallSig:
        '''Parse syscall signature from dict'''
        id_tuple = data.get('id', [0, 0])
        params = [self._parse_param(p) for p in data.get('params', [])]
        self._validate_params(params, f'syscall {name}')
        return_hint = self._parse_return(data.get('return'))
        return SyscallSig(
            name=name,
            subsystem=id_tuple[0],
            cmd=id_tuple[1],
            params=params,
            return_hint=return_hint,
        )

    @classmethod
    def _parse_param(cls, data: Any) -> ParamHint:
        '''Parse parameter hint'''
        if isinstance(data, str):
            raise ValueError(f"Parameter '{data}' missing type")

        name = data.get('name', '')
        param_type = data.get('type')
        if not param_type:
            raise ValueError(f"Parameter '{name}' missing type")

        # Convert list type to union string: [string, number] -> "string | number"
        if isinstance(param_type, list):
            param_type = ' | '.join(param_type)

        return ParamHint(
            name=name,
            type=param_type,
            format=data.get('format'),
            variadic=data.get('variadic', False),
        )

    @classmethod
    def _parse_return(cls, data: Any) -> Optional[ReturnHint]:
        '''Parse return hint'''
        if data is None:
            return None

        if isinstance(data, str):
            return ReturnHint(type=data)

        return ReturnHint(
            name=data.get('name'),
            type=data.get('type'),
            format=data.get('format'),
        )

    def get_function(self, name: str) -> Optional[FunctionSig]:
        '''Get function signature by name'''
        return self.functions.get(name)

    def get_syscall(self, subsystem: int, cmd: int) -> Optional[SyscallSig]:
        '''Get syscall signature by id'''
        return self._syscall_by_id.get((subsystem, cmd))

    def get_enum_value(self, enum_name: str, value: int) -> Optional[str]:
        '''Get enum value name'''
        enum = self.enums.get(enum_name)
        if enum:
            return enum.get(value)

        return None

    def format_value(self, value: int, format_hint: Optional[str]) -> Optional[str]:
        '''Format a value according to hint, returns None if no formatting applied'''
        if format_hint is None:
            return None

        if format_hint == 'hex':
            return f'0x{value:X}'

        # Try as enum
        enum_value = self.get_enum_value(format_hint, value)
        if enum_value:
            return f'{format_hint}.{enum_value}'

        return None
