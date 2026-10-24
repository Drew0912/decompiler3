"""
Structural Analysis for Control Flow Recovery

Implements iterative region reduction with forward reachability analysis
for merge point detection.

Based on:
- Sharir (1980): Structural Analysis
- Cifuentes (1994): Reverse Compilation Techniques
- No More Gotos (2015): Taming Control Flow
"""

from typing import Dict, List, Set, Optional, Tuple
from collections import deque
from collections.abc import Container
from dataclasses import dataclass, field
from enum import Enum, auto


class RegionType(Enum):
    """Types of control flow regions"""

    SEQUENCE = auto()       # Linear sequence of regions
    IF_THEN = auto()        # if (cond) { then }
    IF_THEN_ELSE = auto()   # if (cond) { then } else { else }
    NATURAL_LOOP = auto()   # General natural loop


@dataclass
class Region:
    """A region in the control flow graph"""

    type: RegionType
    exit: Optional[int] = None              # Exit block index (None for infinite loops)


@dataclass
class LoopInfo:
    """Information about a natural loop"""

    header: int
    body: Set[int]
    exits: Set[int] = field(default_factory=set)


class StructuralAnalyzer:
    """
    Structural analysis using iterative region reduction.

    Algorithm:
    1. Build dominator tree (for back edge detection)
    2. Identify natural loops
    3. Iteratively reduce the graph:
       a. Collapse loops first (innermost to outermost)
       b. In acyclic regions, find if-then-else using reachability
       c. Collapse linear sequences
    4. Repeat until no more reductions possible
    """

    def __init__(self, num_blocks: int, successors: Dict[int, List[int]]):
        self.num_blocks = num_blocks
        self.original_successors = successors

        # Working copy of the graph, modified during reduction (the original graph until then)
        self.working_successors: Dict[int, List[int]] = {k: list(v) for k, v in successors.items()}
        self.working_predecessors: Dict[int, List[int]] = self._build_predecessors()

        # Dominator tree (computed once on original graph)
        self.idom: Dict[int, Optional[int]] = {}

        # Loop information
        self.loops: Dict[int, LoopInfo] = {}
        self.back_edges: Set[Tuple[int, int]] = set()

        # Region information
        self.regions: Dict[int, Region] = {}  # entry block -> Region

        # Active nodes (not collapsed into another region)
        self.active_nodes: Set[int] = set(range(num_blocks))

        # Run analysis
        self._analyze()

    def _build_predecessors(self) -> Dict[int, List[int]]:
        preds = {i: [] for i in range(self.num_blocks)}
        for src, succs in self.working_successors.items():
            for dst in succs:
                if dst < self.num_blocks and src not in preds[dst]:
                    preds[dst].append(src)
        return preds

    def _analyze(self):
        """Run full structural analysis"""
        if self.num_blocks == 0:
            return

        # Step 1: Compute dominators on original graph
        self._compute_dominators()

        # Step 2: Identify loops using back edges
        self._identify_loops()

        # Step 3: Iterative reduction
        self._reduce()

    def _compute_dominators(self):
        """Compute dominator tree using iterative dataflow"""
        all_nodes = set(range(self.num_blocks))
        dom = {i: all_nodes.copy() for i in range(self.num_blocks)}
        dom[0] = {0}  # Entry dominates only itself

        changed = True
        while changed:
            changed = False
            for node in range(self.num_blocks):
                if node == 0:
                    continue

                preds = self.working_predecessors.get(node, [])
                if not preds:
                    continue

                new_dom = all_nodes.copy()
                for pred in preds:
                    new_dom &= dom[pred]
                new_dom.add(node)

                if new_dom != dom[node]:
                    dom[node] = new_dom
                    changed = True

        # The immediate dominator is the closest strict dominator: every other strict dominator dominates it
        for node in range(self.num_blocks):
            dominators = dom[node] - {node}
            closest = (candidate for candidate in dominators if dominators - {candidate} <= dom[candidate])
            self.idom[node] = next(closest, None)

    def dominates(self, a: int, b: int) -> bool:
        """Check if a dominates b"""
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
        """Find natural loops using back edges"""
        for src in range(self.num_blocks):
            for dst in self.original_successors.get(src, []):
                if dst < self.num_blocks and self.dominates(dst, src):
                    self.back_edges.add((src, dst))
                    self._build_loop(src, dst)

    def _build_loop(self, tail: int, header: int):
        """Build natural loop from back edge"""
        body = {header, tail}

        # Walk back from the tail, never past the header: a self back edge's loop is the header alone
        worklist = [tail] if tail != header else []

        while worklist:
            node = worklist.pop()
            for pred in self.working_predecessors.get(node, []):
                if pred not in body:
                    body.add(pred)
                    worklist.append(pred)

        if header in self.loops:
            self.loops[header].body |= body
        else:
            self.loops[header] = LoopInfo(header=header, body=body)

        # Find exits over the merged body, so a second back edge cannot report
        # blocks that belong to the loop as exits
        loop = self.loops[header]
        loop.exits = {succ for block in loop.body for succ in self.original_successors.get(block, [])
                      if succ not in loop.body}

    def _reduce(self):
        """One reduction per round: a loop (innermost first), else an if-then-else, else a linear sequence"""
        # The cap is load-bearing: a single-block loop stays reducible, so every round reduces it again
        for _ in range(self.num_blocks * 2):
            if not (self._reduce_loops() or self._reduce_conditionals() or self._reduce_sequences()):
                break

    def _reduce_loops(self) -> bool:
        """Reduce natural loops (innermost first)"""
        # Sort by size (smallest/innermost first)
        sorted_loops = sorted(
            [(h, loop) for h, loop in self.loops.items() if h in self.active_nodes],
            key=lambda x: len(x[1].body)
        )

        for header, loop in sorted_loops:
            # Check if loop is still valid (all blocks active)
            if not loop.body.issubset(self.active_nodes):
                continue

            self.regions[header] = Region(RegionType.NATURAL_LOOP, exit=min(loop.exits, default=None))

            # Collapse loop body (except header) into header
            for block in loop.body:
                if block != header:
                    self.active_nodes.discard(block)

            return True

        return False

    def _reduce_conditionals(self) -> bool:
        """Reduce if-then-else structures"""
        for node in list(self.active_nodes):
            succs = [s for s in self.working_successors.get(node, []) if s in self.active_nodes]

            if len(succs) != 2:
                continue

            true_target, false_target = succs[0], succs[1]

            # Check for back edges (skip, handled by loop reduction)
            if (node, true_target) in self.back_edges or (node, false_target) in self.back_edges:
                continue

            # Find merge point using local reachability
            merge = self._find_merge(self.working_successors, self.active_nodes, true_target, false_target)

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

            self.regions[node] = Region(region_type, exit=merge)

            # Collapse all blocks except entry into entry
            all_blocks = {node} | then_blocks | else_blocks
            for block in all_blocks:
                if block != node:
                    self.active_nodes.discard(block)

            # Update successors: node now goes directly to merge
            self.working_successors[node] = [merge]
            if node not in self.working_predecessors.get(merge, []):
                self.working_predecessors[merge].append(node)

            return True

        return False

    def _reduce_sequences(self) -> bool:
        """Reduce linear sequences A -> B where A has one succ, B has one pred"""
        for node in list(self.active_nodes):
            succs = [s for s in self.working_successors.get(node, []) if s in self.active_nodes]

            if len(succs) != 1:
                continue

            succ = succs[0]

            # Skip back edges
            if (node, succ) in self.back_edges:
                continue

            preds = [p for p in self.working_predecessors.get(succ, []) if p in self.active_nodes]

            if len(preds) != 1:
                continue

            # Collapse succ into node
            self.regions[node] = Region(RegionType.SEQUENCE, exit=succ)

            # Update edges: node inherits succ's successors
            self.working_successors[node] = list(self.working_successors.get(succ, []))
            for s in self.working_successors.get(succ, []):
                # Update predecessor list of s
                if succ in self.working_predecessors.get(s, []):
                    self.working_predecessors[s].remove(succ)
                if node not in self.working_predecessors.get(s, []):
                    self.working_predecessors[s].append(node)

            self.active_nodes.discard(succ)

            return True

        return False

    def _get_region_blocks(self, start: int, stop: int) -> Set[int]:
        """Get all blocks from start to stop (exclusive)"""
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

            for succ in self.working_successors.get(block, []):
                if succ != stop and succ in self.active_nodes and succ not in blocks:
                    # Skip back edges
                    if (block, succ) not in self.back_edges:
                        worklist.append(succ)

        return blocks

    def _find_merge(self, successors: Dict[int, List[int]], active: Container[int], true_target: int,
                    false_target: int) -> Optional[int]:
        """Merge point of the if-else branching to true_target and false_target, searched in successors through the
        active blocks only: the working graph during reduction, the original one (every block active) afterwards"""
        if true_target == false_target:
            return true_target

        # One branch directly targets the other - but only if that edge is an
        # unconditional fallthrough. If the source block is itself a 2-way branch,
        # the target is one of two independent outcomes of its own test (e.g. a
        # chain of equality tests that all share one match target), not an empty
        # tail shared with the other branch - treating it as the merge point would
        # silently drop that target's content for every path except the last.
        if successors.get(false_target, []) == [true_target]:
            return true_target

        if successors.get(true_target, []) == [false_target]:
            return false_target

        # Indirect merge: one target reachable from the other - but only via a
        # chain of unconditional (single-successor) blocks. A multi-hop path that
        # passes through a 2-way branch has the same problem as the direct-edge
        # case above: the candidate is reached because one of that branch's own
        # two outcomes leads there, not because it's an empty shared tail.
        if true_target in self._unconditional_reach(successors, active, false_target):
            return true_target

        if false_target in self._unconditional_reach(successors, active, true_target):
            return false_target

        # Common reachable blocks - reachable from each branch WITHOUT passing
        # through the other branch first. Plain reachability would also count
        # everything downstream of false_target as "reachable from true_target",
        # since true_target eventually reaches false_target itself (that's how a
        # shared-target chain works) - that would keep picking a block inside
        # false_target's own body as a false "merge", just one step further along.
        reach_true = self._forward_reach(successors, active, true_target, barrier=false_target)
        reach_false = self._forward_reach(successors, active, false_target, barrier=true_target)

        # The targets themselves are never common: each search stops at the other
        common = reach_true.keys() & reach_false.keys()
        if not common:
            return None

        # Return nearest (minimum combined distance, then block order)
        return min(common, key=lambda b: (reach_true[b] + reach_false[b], b))

    def _unconditional_reach(self, successors: Dict[int, List[int]], active: Container[int], start: int) -> Set[int]:
        """start and the blocks it reaches along unconditional (single-successor) edges

        Stops at the first 2-way branch instead of following either of its edges,
        so a block reached only through one outcome of a decision made along the
        way is never mistaken for start's own empty/trivial continuation.
        """
        reach = {start}
        block = start

        while block in active and len(successors.get(block, [])) == 1:
            succ = successors[block][0]
            if (block, succ) in self.back_edges or succ in reach:
                break

            reach.add(succ)
            block = succ

        return reach

    def _forward_reach(self, successors: Dict[int, List[int]], active: Container[int], start: int,
                       barrier: int) -> Dict[int, int]:
        """Distances of the active blocks reachable from start, skipping back edges

        barrier is never entered or traversed past - used to keep a branch's own
        reachable set from including whatever lies beyond the other branch's
        target once the two eventually converge.
        """
        reach = {}
        queue = deque([(start, 0)])

        while queue:
            block, depth = queue.popleft()
            if block in reach or block not in active or block == barrier:
                continue

            reach[block] = depth
            for succ in successors.get(block, []):
                if (block, succ) not in self.back_edges:
                    queue.append((succ, depth + 1))

        return reach

    # ========== Public API ==========

    def find_merge_point(self, cond_block: int, true_target: int, false_target: int,
                         stop: Optional[int] = None) -> Optional[int]:
        """
        Merge point of the if ending cond_block, whose arms stop at stop (the enclosing merge or
        loop header, None at function level): the heuristic's answer when it is a real merge (see
        _MergeScope), else the nearest real merge both arms reach, else None.
        """
        merge = self._heuristic_merge_point(cond_block, true_target, false_target)
        if true_target == false_target or (merge is not None and merge == stop):
            return merge

        scope = _MergeScope(self, cond_block, stop)
        if merge is not None and scope.is_valid(merge):
            return merge

        return scope.nearest_valid_join(true_target, false_target)

    def _heuristic_merge_point(self, cond_block: int, true_target: int, false_target: int) -> Optional[int]:
        """
        Merge point candidate for if-else.

        First checks if a region was identified during structural analysis.
        Falls back to reachability search on the original graph.
        """
        # Check if we have a pre-computed region
        if cond_block in self.regions:
            region = self.regions[cond_block]
            if region.type in (RegionType.IF_THEN, RegionType.IF_THEN_ELSE):
                return region.exit

        # Use reachability on ORIGINAL graph (not the modified one)
        return self._find_merge(self.original_successors, range(self.num_blocks), true_target, false_target)

    def should_invert_condition(self, true_target: int, false_target: int) -> bool:
        """
        Check if condition should be inverted for canonical if-else-if structure.

        In if-else-if chains, MLIL often has inverted conditions:
            if (!cond) goto next_check else case_body

        For canonical HLIL, we want:
            if (cond) { case_body } else { next_check }

        Structural detection: true_target has 2 successors (another condition),
        while false_target does not look like a continuation.
        """
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

    def get_loop_info(self, header: int) -> Optional[LoopInfo]:
        """Get loop information"""
        return self.loops.get(header)


class _MergeScope:
    """
    The part of the CFG an if's merge point must lie in, and what makes a block a real merge.

    Inside the innermost natural loop around the if, a path ends at a back edge, at an edge
    leaving the loop body or at its header (break / continue); anywhere, it ends at a return and
    at the enclosing stop. A merge M is valid when paths reach it inside this scope, no path gets
    around M into code that follows M (falling out of an arm would miss that code or run it
    twice), and - unless the stop is the loop header, where a jump is an explicit continue - no
    path reaches the enclosing stop without passing M (falling out there would run M first).
    """

    def __init__(self, analyzer: StructuralAnalyzer, cond_block: int, stop: Optional[int]):
        self.analyzer = analyzer
        self.cond_block = cond_block
        self.stop = stop

        # Natural loops are nested or disjoint, so the smallest one holding the if is unique
        loops = [loop for loop in analyzer.loops.values() if cond_block in loop.body]
        self.loop = min(loops, key=lambda loop: len(loop.body)) if loops else None

        self.stop_falls_out = stop is not None and not (self.loop is not None and stop == self.loop.header)
        self._reach_cache: Dict[Tuple[int, Optional[int]], Dict[int, int]] = {}

    def follows(self, src: int, dst: int) -> bool:
        """Whether a path inside the scope continues along src -> dst"""
        if dst >= self.analyzer.num_blocks or dst == self.stop or (src, dst) in self.analyzer.back_edges:
            return False

        return self.loop is None or (dst in self.loop.body and dst != self.loop.header)

    def reach(self, start: int, barrier: Optional[int] = None) -> Dict[int, int]:
        """Blocks reachable from start inside the scope without entering barrier, with distances"""
        key = (start, barrier)
        cached = self._reach_cache.get(key)
        if cached is not None:
            return cached

        dist: Dict[int, int] = {}
        queue = deque([(start, 0)])

        while queue:
            block, depth = queue.popleft()
            if block in dist or block == barrier:
                continue

            dist[block] = depth
            for succ in self.analyzer.original_successors.get(block, []):
                if self.follows(block, succ):
                    queue.append((succ, depth + 1))

        self._reach_cache[key] = dist
        return dist

    def is_valid(self, merge: int) -> bool:
        """Whether merge is a real merge of the if (see the class docstring)"""
        before = self.reach(self.cond_block, barrier=merge)
        successors = self.analyzer.original_successors

        if not any(merge in successors.get(block, []) and self.follows(block, merge) for block in before):
            return False

        if self.stop_falls_out and any(self.stop in successors.get(block, []) for block in before):
            return False

        return not (before.keys() & self.reach(merge).keys())

    def nearest_valid_join(self, true_target: int, false_target: int) -> Optional[int]:
        """The nearest valid merge that both arms reach (an arm target itself counts), or None"""
        reach_true = self.reach(true_target) if self.follows(self.cond_block, true_target) else {}
        reach_false = self.reach(false_target) if self.follows(self.cond_block, false_target) else {}
        joins = sorted(reach_true.keys() & reach_false.keys(), key=lambda b: (reach_true[b] + reach_false[b], b))

        for merge in joins:
            if self.is_valid(merge):
                return merge

        return None
