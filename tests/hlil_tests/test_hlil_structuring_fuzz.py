#!/usr/bin/env python3
'''Random CFGs through the whole HLIL pipeline, checked against their MLIL run by run.

Each CFG has 4-10 blocks ending in a return, a goto or an if; most blocks make one call, some
gotos only jump on (passthrough chains) and some ifs test a constant (dead arms). For every
assignment of the parameters the HLIL must make the same calls and end the same way as the
MLIL, or stop at an unstructured-jump node exactly where the MLIL run jumps to its target
(hlil_cfg_utils.classify). tools/hlil_path_check.py must agree with that verdict. Line markers in every
block (goto-only blocks too) change no run and no node.

Irreducible CFGs may need nodes (HLIL has no goto). A reducible one could always be structured,
so a node there is a gap the converter still has: the seeds that get one today are pinned below,
and any other seed getting one fails (docs/FUTURE_WORK.md, Structuring the Remaining
Reducible Shapes).
'''

from pathlib import Path
import random
import sys
import unittest
from typing import Dict, List, Set

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from hlil_path_check import check_function
from ir.hlil.hlil import (
    HLILBreak, HLILCall, HLILContinue, HLILDoWhile, HLILIf, HLILReturn, HLILUnstructured, HLILWhile, iter_tree,
)
from tests.shared.hlil_cfg_utils import BlockSpec, build_function, to_hlil, classify, unstructured_nodes, with_markers

SEEDS = 1000
MIN_BLOCKS = 4
BLOCK_COUNTS = 7
RETURN_SHARE = 0.22
GOTO_SHARE = 0.32
PASSTHROUGH_SHARE = 0.35
CONSTANT_SHARE = 0.12

# Reducible CFGs among the seeds that still get a node (loud, never a wrong run)
PINNED_REDUCIBLE_WITH_NODES = [19, 54, 419, 754, 951, 969]


def reachable_from_entry(successors: List[tuple]) -> Set[int]:
    seen, todo = set(), [0]
    while todo:
        block = todo.pop()
        if block not in seen:
            seen.add(block)
            todo.extend(successors[block])

    return seen


def random_cfg(seed: int) -> Dict[str, BlockSpec]:
    rng = random.Random(seed)
    count = MIN_BLOCKS + seed % BLOCK_COUNTS

    while True:
        kinds, successors = [], []
        for i in range(count):
            draw = rng.random()
            if draw < RETURN_SHARE:
                kinds.append('ret')
                successors.append(())

            elif draw < RETURN_SHARE + GOTO_SHARE:
                kinds.append('goto')
                successors.append((rng.randrange(count),))

            else:
                kinds.append('if')
                successors.append(tuple(rng.sample(range(count), 2)))

        if reachable_from_entry(successors) == set(range(count)) and 'ret' in kinds:
            break

    blocks: Dict[str, BlockSpec] = {}
    for i in range(count):
        passthrough = kinds[i] == 'goto' and i != 0 and rng.random() < PASSTHROUGH_SHARE
        calls = [] if passthrough else [f'A{i}']

        if kinds[i] == 'ret':
            terminal = ('ret', i)

        elif kinds[i] == 'goto':
            terminal = ('goto', f'B{successors[i][0]}')

        else:
            condition = rng.randrange(2) if rng.random() < CONSTANT_SHARE else f'p{i}'
            terminal = ('if', condition, f'B{successors[i][0]}', f'B{successors[i][1]}')

        blocks[f'B{i}'] = (calls, terminal)

    return blocks


def terminal_targets(terminal: tuple) -> List[str]:
    if terminal[0] == 'if':
        return [terminal[2], terminal[3]]

    if terminal[0] == 'goto':
        return [terminal[1]]

    return []


def is_reducible(blocks: Dict[str, BlockSpec]) -> bool:
    '''No cycle is left once every edge to a block dominating its source is removed'''
    labels = list(blocks)
    successors = {label: terminal_targets(terminal) for label, (_, terminal) in blocks.items()}

    dominators = {label: set(labels) for label in labels}
    dominators[labels[0]] = {labels[0]}
    changed = True
    while changed:
        changed = False
        for label in labels[1:]:
            preds = [p for p in labels if label in successors[p]]
            new = set.intersection(*(dominators[p] for p in preds)) | {label} if preds else {label}
            if new != dominators[label]:
                dominators[label], changed = new, True

    forward = {label: [s for s in successors[label] if s not in dominators[label]] for label in labels}
    state: Dict[str, int] = {}

    def has_cycle(label: str) -> bool:
        state[label] = 1
        for succ in forward[label]:
            if state.get(succ) == 1 or (succ not in state and has_cycle(succ)):
                return True

        state[label] = 2
        return False

    return not any(has_cycle(label) for label in labels if label not in state)


class TestStructuringFuzz(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.results = []
        for seed in range(SEEDS):
            blocks = random_cfg(seed)
            func = build_function(f'fuzz_{seed}', blocks)
            hlil = to_hlil(func)
            verdict, env = classify(func, hlil)
            cls.results.append((seed, blocks, verdict, env, check_function(func, hlil), unstructured_nodes(hlil)))

    def test_no_run_differs_from_mlil(self):
        wrong = [(seed, env) for seed, _, verdict, env, _, _ in self.results if verdict == 'wrong']
        self.assertEqual(wrong, [])

    def test_path_check_agrees_with_the_runs(self):
        disagree = []
        for seed, _, verdict, _, check, nodes in self.results:
            if verdict == 'ok' and (not check.ok or check.unstructured or nodes):
                disagree.append((seed, 'ok run, check reports', check.missing[:2], check.extra[:2], check.uncovered[:2]))

            if verdict == 'loud' and not check.unstructured:
                disagree.append((seed, 'loud run, check sees no node'))

        self.assertEqual(disagree, [])

    def test_nodes_on_reducible_cfgs_are_pinned(self):
        reducible_with_nodes = [seed for seed, blocks, _, _, _, nodes in self.results if nodes and is_reducible(blocks)]
        self.assertEqual(reducible_with_nodes, PINNED_REDUCIBLE_WITH_NODES)

    def test_markers_in_every_block_change_no_run(self):
        changed = []
        for seed, blocks, verdict, env, _, nodes in self.results:
            func = build_function(f'fuzz_{seed}', with_markers(blocks, every_block = True))
            hlil = to_hlil(func)
            if classify(func, hlil) != (verdict, env) or len(unstructured_nodes(hlil)) != len(nodes):
                changed.append(seed)

        self.assertEqual(changed, [])


SHAPE_KINDS = (HLILIf, HLILWhile, HLILDoWhile, HLILBreak, HLILContinue, HLILReturn, HLILUnstructured, HLILCall)

# Shapes, not meaning: a change to the merge heuristics or the clone limits shows here. When a deliberate change
# moves one, check the new shape is as good, then re-pin from `python tests/hlil_tests/test_hlil_structuring_fuzz.py
# --print`. seed: (verdict, ifs, whiles, do-whiles, breaks, continues, returns, unstructured-jump nodes, calls)
SEED_SHAPES = {
    7:    ('ok', 2, 1, 0, 0, 2, 1, 0, 4),
    21:   ('ok', 2, 1, 0, 0, 1, 1, 0, 4),
    84:   ('ok', 2, 2, 0, 1, 1, 1, 0, 4),
    116:  ('ok', 6, 3, 0, 0, 0, 1, 0, 9),
    119:  ('ok', 2, 2, 0, 2, 2, 1, 0, 4),
    180:  ('ok', 5, 3, 0, 1, 1, 2, 0, 10),
    182:  ('ok', 2, 1, 0, 0, 1, 1, 0, 4),
    203:  ('ok', 2, 2, 0, 2, 2, 1, 0, 4),
    230:  ('ok', 6, 1, 0, 3, 1, 3, 0, 10),
    404:  ('ok', 7, 2, 0, 2, 2, 3, 0, 13),
    919:  ('loud', 6, 0, 0, 0, 0, 1, 6, 7),
    1069: ('loud', 5, 0, 0, 0, 0, 1, 2, 9),
    1121: ('loud', 13, 0, 0, 0, 0, 1, 8, 20),
    1136: ('ok', 2, 2, 0, 2, 1, 1, 0, 6),
    1147: ('ok', 5, 3, 0, 2, 3, 2, 0, 11),
    1202: ('ok', 15, 4, 0, 3, 9, 3, 0, 18),
    1208: ('loud', 6, 4, 0, 7, 1, 1, 2, 8),
    1427: ('ok', 10, 2, 0, 0, 0, 7, 0, 17),
    1579: ('ok', 2, 0, 0, 0, 0, 1, 0, 7),
    1760: ('ok', 3, 1, 0, 0, 1, 1, 0, 7),
    4128: ('ok', 6, 1, 0, 3, 1, 2, 0, 10),
}


def shape_of(seed: int) -> tuple:
    func = build_function(f'fuzz_{seed}', random_cfg(seed))
    hlil = to_hlil(func)
    nodes = list(iter_tree(hlil.body))
    return (classify(func, hlil)[0], *(sum(isinstance(node, kind) for node in nodes) for kind in SHAPE_KINDS))


class TestPinnedSeedShapes(unittest.TestCase):
    def test_each_seed_keeps_its_shape(self):
        for seed, shape in SEED_SHAPES.items():
            with self.subTest(seed = seed):
                self.assertEqual(shape_of(seed), shape)


if __name__ == '__main__':
    if sys.argv[1:] == ['--print']:
        for seed in SEED_SHAPES:
            print(f'    {seed}: {shape_of(seed)!r},')

    else:
        unittest.main()
