'''Falcom ED9 Type Signatures - Extract signatures from ScpParser'''

from typing import Optional
from ir.mlil.mlil_types import MLILType, FunctionSignatureDB
from ...parser.scp import ScpParser


class ED9TypeSignatures(FunctionSignatureDB):
    '''ED9 function signature database with ScpParser integration'''

    def __init__(self, parser: ScpParser):
        self.parser = parser

        # Syscall signatures: (subsystem, cmd) -> type
        self.syscall_sigs = {}

        # Script call signatures: (module, func) -> type
        self.script_call_sigs = {}

        # Known function patterns
        self.function_pattern_sigs = {
            'Init': MLILType.void_type(),
            'Update': MLILType.void_type(),
            'Cleanup': MLILType.void_type(),
            'OnEnter': MLILType.void_type(),
            'OnExit': MLILType.void_type(),
        }

        self._function_cache = {}

    def get_syscall_return_type(self, subsystem: int, cmd: int) -> Optional[MLILType]:
        return self.syscall_sigs.get((subsystem, cmd))

    def get_script_call_return_type(self, module: str, func: str) -> Optional[MLILType]:
        return self.script_call_sigs.get((module, func))

    def get_call_return_type(self, target) -> Optional[MLILType]:
        if not isinstance(target, str):
            return None

        if target in self._function_cache:
            return self._function_cache[target]

        if target in self.function_pattern_sigs:
            return self.function_pattern_sigs[target]

        # Extract from parser
        func = self.parser.function_map.get(target)
        if func:
            return_type = self._infer_function_return_type(func)
            self._function_cache[target] = return_type
            return return_type

        return None

    def _infer_function_return_type(self, func) -> MLILType:
        '''Heuristic: infer type from function name patterns'''
        name_lower = func.name.lower()

        # Event handlers -> void
        if any(pattern in name_lower for pattern in ['_talk', '_event', '_init', '_update']):
            return MLILType.void_type()

        # Getters -> int
        if name_lower.startswith('get') or name_lower.startswith('is') or name_lower.startswith('has'):
            return MLILType.int_type()

        return MLILType.unknown()
