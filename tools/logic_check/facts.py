"""The facts one layer's evaluation gives, compared across layers: each effect with its argument trees and guard, each
branch with its condition and targets, which effect can run next, each value a loop carries into its header"""

from dataclasses import dataclass, field
from typing import Callable, Hashable

from .formulas import TRUE

RETURN_KEY = (None, 'return')   # a gated layer's returns, one effect: HLIL may merge two into one (a common return)


@dataclass
class Effect:
    address: int
    kind: str               # 'call' (debug.log too), 'script call', 'syscall', 'store global', 'store deref', 'return';
                            # gated, a loop's 'loop' and 'loop continue' (GatedNaming.loop_effects)
    target: Hashable
    args: tuple
    guard: frozenset = frozenset()      # named by address: the arms it runs under (AddressNaming.set_guard)
    inside: frozenset = frozenset()     # gated: the loops (names) whose body it is in (GatedNaming.mark_loops)
    after: frozenset = frozenset()      # gated: the loops (names) whose exits lead to it
    storage: tuple = ()     # what it passes on besides args, (neutral key, value) pairs: a call the locals they point
                            # to (VMEffects.local_values), a return the other registers (VMEffects.return_registers)
    guard_formula: tuple = TRUE     # gated: the formula it runs under (GatedNaming.guard_formula)

    @property
    def key(self) -> tuple:
        return (self.address, self.kind)


@dataclass
class Branch:
    address: int
    condition: tuple
    true_target: int        # target block start addresses (HLIL: node indexes)
    false_target: int


@dataclass
class Facts:
    effects: dict[tuple, list[Effect]] = field(default_factory=dict)
    branches: dict[int, Branch] = field(default_factory=dict)
    next_effects: dict[Hashable, frozenset] = field(default_factory=dict)
    # (header, key, incoming edge) -> each copy of the loop's (formula it runs under, value): HLIL may rebuild one
    loop_values: dict[tuple, list[tuple]] = field(default_factory=dict)
    neutral_key: Callable[[tuple], tuple] | None = None    # a layer's own storage key the way every layer names it
    # gated: loop name -> (the formula it runs under, the formula it ends under: an edge leaving its body is taken)
    loop_runs: dict[Hashable, tuple] = field(default_factory=dict)
    # gated: a merge cut at the phi depth, its fingerprint -> its gamma (state.merged_value, Namer.opened)
    deep_choices: dict[bytes, tuple] = field(default_factory=dict)
    unstructured: list = field(default_factory=list)        # HLIL: the reachable jumps it could not express

    def neutral(self, key: tuple) -> tuple:
        """key the way every layer names it"""
        return key if self.neutral_key is None else self.neutral_key(key)
