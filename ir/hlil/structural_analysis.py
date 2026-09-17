'''
Structural Analysis for Control Flow Recovery

Implements iterative region reduction with forward reachability analysis
for merge point detection.

Based on:
- Sharir (1980): Structural Analysis
- Cifuentes (1994): Reverse Compilation Techniques
- No More Gotos (2015): Taming Control Flow
'''

from typing import Dict, List, Set, Optional, Tuple
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto


class RegionType(Enum):
    '''Types of control flow regions'''
    BLOCK = auto()          # Basic block
    SEQUENCE = auto()       # Linear sequence of regions
    IF_THEN = auto()        # if (cond) { then }
    IF_THEN_ELSE = auto()   # if (cond) { then } else { else }
    WHILE = auto()          # while (cond) { body }
    DO_WHILE = auto()       # do { body } while (cond)
    NATURAL_LOOP = auto()   # General natural loop
    SWITCH = auto()         # switch/case


@dataclass
class Region:
    '''A region in the control flow graph'''
    type: RegionType
    entry: int                              # Entry block index
    exit: Optional[int] = None              # Exit block index (None for infinite loops)
    blocks: Set[int] = field(default_factory=set)  # All blocks in this region
    children: List['Region'] = field(default_factory=list)  # Nested regions
    condition_block: Optional[int] = None   # Block containing the condition (for if/loop)

    def __hash__(self):
        return hash(self.entry)


@dataclass
class LoopInfo:
    '''Information about a natural loop'''
    header: int
    body: Set[int]
    back_edges: List[Tuple[int, int]]
    exits: Set[int] = field(default_factory=set)


class StructuralAnalyzer:
    '''
    Structural analysis using iterative region reduction.

    Algorithm:
    1. Build dominator tree (for back edge detection)
    2. Identify natural loops
    3. Iteratively reduce the graph:
       a. Collapse loops first (innermost to outermost)
       b. In acyclic regions, find if-then-else using reachability
       c. Collapse linear sequences
    4. Repeat until no more reductions possible
    '''

    def __init__(self, num_blocks: int, successors: Dict[int, List[int]]):
        self.num_blocks = num_blocks
        self.original_successors = successors

        # Working copy of the graph (modified during reduction)
        self.successors: Dict[int, List[int]] = {k: list(v) for k, v in successors.items()}
        self.predecessors: Dict[int, List[int]] = self._build_predecessors()

        # Dominator tree (computed once on original graph)
        self.idom: Dict[int, Optional[int]] = {}

        # Loop information
        self.loops: Dict[int, LoopInfo] = {}
        self.back_edges: Set[Tuple[int, int]] = set()

        # Region information
        self.regions: Dict[int, Region] = {}  # entry block -> Region

        # Collapsed nodes: original block -> representative block
        self.collapsed: Dict[int, int] = {}

        # Active nodes (not collapsed into another region)
        self.active_nodes: Set[int] = set(range(num_blocks))

        # Run analysis
        self._analyze()

    def _build_predecessors(self) -> Dict[int, List[int]]:
        preds = {i: [] for i in range(self.num_blocks)}
        for src, succs in self.successors.items():
            for dst in succs:
                if dst < self.num_blocks and src not in preds[dst]:
                    preds[dst].append(src)
        return preds

    def _analyze(self):
        '''Run full structural analysis'''
        if self.num_blocks == 0:
            return

        # Step 1: Compute dominators on original graph
        self._compute_dominators()

        # Step 2: Identify loops using back edges
        self._identify_loops()

        # Step 3: Iterative reduction
        self._reduce()

    def _compute_dominators(self):
        '''Compute dominator tree using iterative dataflow'''
        all_nodes = set(range(self.num_blocks))
        dom = {i: all_nodes.copy() for i in range(self.num_blocks)}
        dom[0] = {0}  # Entry dominates only itself

        changed = True
        while changed:
            changed = False
            for node in range(self.num_blocks):
                if node == 0:
                    continue

                preds = self.predecessors.get(node, [])
                if not preds:
                    continue

                new_dom = all_nodes.copy()
                for pred in preds:
                    new_dom &= dom[pred]
                new_dom.add(node)

                if new_dom != dom[node]:
                    dom[node] = new_dom
                    changed = True

        # Extract immediate dominators
        for node in range(self.num_blocks):
            if node == 0:
                self.idom[node] = None
                continue

            dominators = dom[node] - {node}
            if not dominators:
                self.idom[node] = None
                continue

            # Find immediate dominator (closest dominator that dominates all others)
            idom = None
            for candidate in dominators:
                is_idom = True
                for other in dominators:
                    # candidate is idom if it dominates all other dominators
                    if other != candidate and other not in dom[candidate]:
                        is_idom = False
                        break
                if is_idom:
                    idom = candidate
                    break

            self.idom[node] = idom

    def dominates(self, a: int, b: int) -> bool:
        '''Check if a dominates b'''
        if a == b:
            return True
        current = b
        visited = set()
        while current is not None and current not in visited:
            visited.add(current)
            if self.idom.get(current) == a:
                return True
            current = self.idom.get(current)
        return False

    def _identify_loops(self):
        '''Find natural loops using back edges'''
        for src in range(self.num_blocks):
            for dst in self.original_successors.get(src, []):
                if dst < self.num_blocks and self.dominates(dst, src):
                    self.back_edges.add((src, dst))
                    self._build_loop(src, dst)

    def _build_loop(self, tail: int, header: int):
        '''Build natural loop from back edge'''
        body = {header, tail}
        worklist = [tail]

        while worklist:
            node = worklist.pop()
            for pred in self.predecessors.get(node, []):
                if pred not in body:
                    body.add(pred)
                    worklist.append(pred)

        if header in self.loops:
            self.loops[header].back_edges.append((tail, header))
            self.loops[header].body |= body
        else:
            self.loops[header] = LoopInfo(
                header=header,
                body=body,
                back_edges=[(tail, header)]
            )

        # Find exits over the merged body, so a second back edge cannot report
        # blocks that belong to the loop as exits
        merged_body = self.loops[header].body
        exits = set()
        for block in merged_body:
            for succ in self.original_successors.get(block, []):
                if succ not in merged_body:
                    exits.add(succ)
        self.loops[header].exits = exits

    def _reduce(self):
        '''Iterative region reduction'''
        max_iterations = self.num_blocks * 2
        iteration = 0

        while iteration < max_iterations:
            iteration += 1
            reduced = False

            # Priority 1: Collapse loops (innermost first)
            reduced |= self._reduce_loops()

            if reduced:
                continue

            # Priority 2: Collapse if-then-else in acyclic regions
            reduced |= self._reduce_conditionals()

            if reduced:
                continue

            # Priority 3: Collapse linear sequences
            reduced |= self._reduce_sequences()

            if not reduced:
                break

    def _reduce_loops(self) -> bool:
        '''Reduce natural loops (innermost first)'''
        # Sort by size (smallest/innermost first)
        sorted_loops = sorted(
            [(h, l) for h, l in self.loops.items() if h in self.active_nodes],
            key=lambda x: len(x[1].body)
        )

        for header, loop in sorted_loops:
            # Check if loop is still valid (all blocks active)
            if not loop.body.issubset(self.active_nodes):
                continue

            # Create loop region
            region = Region(
                type=RegionType.NATURAL_LOOP,
                entry=header,
                exit=min(loop.exits) if loop.exits else None,
                blocks=loop.body.copy(),
                condition_block=header
            )

            self.regions[header] = region

            # Collapse loop body (except header) into header
            for block in loop.body:
                if block != header:
                    self._collapse_into(block, header)

            return True

        return False

    def _reduce_conditionals(self) -> bool:
        '''Reduce if-then-else structures'''
        for node in list(self.active_nodes):
            succs = [s for s in self.successors.get(node, []) if s in self.active_nodes]

            if len(succs) != 2:
                continue

            true_target, false_target = succs[0], succs[1]

            # Check for back edges (skip, handled by loop reduction)
            if (node, true_target) in self.back_edges or (node, false_target) in self.back_edges:
                continue

            # Find merge point using local reachability
            merge = self._find_local_merge(true_target, false_target)

            if merge is None:
                continue

            # Determine region type
            if merge == true_target:
                # if-then (else branch only)
                region_type = RegionType.IF_THEN
                then_blocks = set()
                else_blocks = self._get_region_blocks(false_target, merge)

            elif merge == false_target:
                # if-then (then branch only)
                region_type = RegionType.IF_THEN
                then_blocks = self._get_region_blocks(true_target, merge)
                else_blocks = set()

            else:
                # if-then-else
                region_type = RegionType.IF_THEN_ELSE
                then_blocks = self._get_region_blocks(true_target, merge)
                else_blocks = self._get_region_blocks(false_target, merge)

            # Create region
            all_blocks = {node} | then_blocks | else_blocks
            region = Region(
                type=region_type,
                entry=node,
                exit=merge,
                blocks=all_blocks,
                condition_block=node
            )

            self.regions[node] = region

            # Collapse all blocks except entry into entry
            for block in all_blocks:
                if block != node:
                    self._collapse_into(block, node)

            # Update successors: node now goes directly to merge
            self.successors[node] = [merge]
            if node in self.predecessors.get(merge, []):
                pass  # Already a predecessor
            else:
                self.predecessors[merge].append(node)

            return True

        return False

    def _reduce_sequences(self) -> bool:
        '''Reduce linear sequences A -> B where A has one succ, B has one pred'''
        for node in list(self.active_nodes):
            succs = [s for s in self.successors.get(node, []) if s in self.active_nodes]

            if len(succs) != 1:
                continue

            succ = succs[0]

            # Skip back edges
            if (node, succ) in self.back_edges:
                continue

            preds = [p for p in self.predecessors.get(succ, []) if p in self.active_nodes]

            if len(preds) != 1:
                continue

            # Collapse succ into node
            region = Region(
                type=RegionType.SEQUENCE,
                entry=node,
                exit=succ,
                blocks={node, succ}
            )

            self.regions[node] = region

            # Update edges: node inherits succ's successors
            self.successors[node] = list(self.successors.get(succ, []))
            for s in self.successors.get(succ, []):
                # Update predecessor list of s
                if succ in self.predecessors.get(s, []):
                    self.predecessors[s].remove(succ)
                if node not in self.predecessors.get(s, []):
                    self.predecessors[s].append(node)

            self._collapse_into(succ, node)

            return True

        return False

    def _collapse_into(self, block: int, representative: int):
        '''Collapse a block into its representative'''
        self.collapsed[block] = representative
        self.active_nodes.discard(block)

    def _get_region_blocks(self, start: int, stop: int) -> Set[int]:
        '''Get all blocks from start to stop (exclusive)'''
        if start == stop:
            return set()

        blocks = set()
        worklist = [start]

        while worklist:
            block = worklist.pop()
            if block == stop or block in blocks:
                continue
            if block not in self.active_nodes:
                continue

            blocks.add(block)

            for succ in self.successors.get(block, []):
                if succ != stop and succ in self.active_nodes and succ not in blocks:
                    # Skip back edges
                    if (block, succ) not in self.back_edges:
                        worklist.append(succ)

        return blocks

    def _find_local_merge(self, true_target: int, false_target: int) -> Optional[int]:
        '''
        Find merge point for if-else within a local acyclic region.
        Used during iterative reduction on the working graph.
        '''
        if true_target == false_target:
            return true_target

        # One branch directly targets the other
        if true_target in self.successors.get(false_target, []):
            return true_target

        if false_target in self.successors.get(true_target, []):
            return false_target

        # Forward reachability from each branch
        reach_true = self._forward_reach(true_target)
        reach_false = self._forward_reach(false_target)

        # Indirect merge: one target reachable from the other
        if true_target in reach_false:
            return true_target

        if false_target in reach_true:
            return false_target

        # Common reachable blocks
        common = set(reach_true.keys()) & set(reach_false.keys())
        common.discard(true_target)
        common.discard(false_target)

        if not common:
            return None

        # Return nearest (minimum combined distance)
        return min(common, key=lambda b: reach_true[b] + reach_false[b])

    def _forward_reach(self, start: int) -> Dict[int, int]:
        '''Forward reachability, skipping back edges and collapsed nodes'''
        reach = {}
        queue = deque([(start, 0)])

        while queue:
            block, depth = queue.popleft()

            if block in reach:
                continue

            if block not in self.active_nodes:
                continue

            reach[block] = depth

            for succ in self.successors.get(block, []):
                # Skip back edges
                if (block, succ) in self.back_edges:
                    continue

                if succ not in reach and succ in self.active_nodes:
                    queue.append((succ, depth + 1))

        return reach

    # ========== Public API ==========

    def find_merge_point(self, cond_block: int, true_target: int, false_target: int) -> Optional[int]:
        '''
        Find merge point for if-else.

        First checks if a region was identified during structural analysis.
        Falls back to reachability search on the original graph.
        '''
        # Check if we have a pre-computed region
        if cond_block in self.regions:
            region = self.regions[cond_block]
            if region.type in (RegionType.IF_THEN, RegionType.IF_THEN_ELSE):
                return region.exit

        # Use reachability on ORIGINAL graph (not the modified one)
        return self._find_merge_on_original(true_target, false_target)

    def _find_merge_on_original(self, true_target: int, false_target: int) -> Optional[int]:
        '''Find merge point using original (unmodified) CFG'''
        if true_target == false_target:
            return true_target

        # One branch directly targets the other
        if true_target in self.original_successors.get(false_target, []):
            return true_target

        if false_target in self.original_successors.get(true_target, []):
            return false_target

        # Forward reachability on original graph
        reach_true = self._forward_reach_original(true_target)
        reach_false = self._forward_reach_original(false_target)

        # Indirect merge: one target reachable from the other
        if true_target in reach_false:
            return true_target

        if false_target in reach_true:
            return false_target

        # Common reachable blocks
        common = set(reach_true.keys()) & set(reach_false.keys())
        common.discard(true_target)
        common.discard(false_target)

        if not common:
            return None

        # Return nearest (minimum combined distance)
        return min(common, key=lambda b: reach_true[b] + reach_false[b])

    def _forward_reach_original(self, start: int) -> Dict[int, int]:
        '''Forward reachability on original graph, skipping back edges'''
        reach = {}
        queue = deque([(start, 0)])

        while queue:
            block, depth = queue.popleft()

            if block in reach:
                continue

            reach[block] = depth

            for succ in self.original_successors.get(block, []):
                # Skip back edges
                if (block, succ) in self.back_edges:
                    continue

                if succ not in reach:
                    queue.append((succ, depth + 1))

        return reach

    def should_invert_condition(self, true_target: int, false_target: int) -> bool:
        '''
        Check if condition should be inverted for canonical if-else-if structure.

        In if-else-if chains, MLIL often has inverted conditions:
            if (!cond) goto next_check else case_body

        For canonical HLIL, we want:
            if (cond) { case_body } else { next_check }

        Structural detection: true_target has 2 successors (another condition),
        while false_target does not look like a continuation.
        '''
        # Don't invert if true_target is a loop header
        if true_target in self.loops:
            return False

        # Check if true_target is a condition block (has 2 successors)
        true_succs = self.original_successors.get(true_target, [])
        if len(true_succs) != 2:
            return False

        # Don't invert if false_target is also a condition block (diamond pattern)
        # In this case, both branches are continuations, not if-else-if
        false_succs = self.original_successors.get(false_target, [])
        if len(false_succs) == 2 and false_target not in self.loops:
            return False

        return True

    def is_loop_header(self, block: int) -> bool:
        '''Check if block is a loop header'''
        return block in self.loops

    def get_loop_info(self, header: int) -> Optional[LoopInfo]:
        '''Get loop information'''
        return self.loops.get(header)

    def is_back_edge(self, src: int, dst: int) -> bool:
        '''Check if edge is a back edge'''
        return (src, dst) in self.back_edges

    def get_region(self, block: int) -> Optional[Region]:
        '''Get region starting at block'''
        return self.regions.get(block)
