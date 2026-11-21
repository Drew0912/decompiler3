"""The HLIL DSL's ED9 lowering (docs/dsl/HLIL_DSL.md, Recompile Path): an HLIL body's statements as the LLIL opcodes the
compiler writes for them, handed to a sink one at a time - at compile time the writer's opcode functions
(llil_sink.py). It starts with the stack holding exactly the parameters (slot 0 the last); a local's slot is where
its Let pushed it, and its block's end pops it; arguments are pushed last first; a call's result is read from REGS[0];
an If's arms jump past themselves when their condition is 0 (POP_JMP_ZERO) and to its end after their block; a While
tests at its head, jumps past itself when the test is 0 and back to the head after its block; Break and Continue pop
the locals of each block they leave, a POP per block from the loop's own, then jump past the loop or to its head. Each
opcode is at the line of the node it lowers, a leaf's at its user's. HLIL's operators and the constants' kinds become
ED9's opcodes here"""

from itertools import pairwise
from typing import NamedTuple, Protocol

from assembler import OperandFormat, OperandType
from ir.core import operators
from ...assembler import ED9Opcode
from ...assembler.vm import CALLER_FRAME_SLOTS, LOCAL_SETUP_SLOTS, RESULT_REGISTER, WORD_SIZE
from ...structs.scp_types import RawInt
from .build import Build
from .calls import BodyStatement, Call, LocalCall, ScriptCall
from .control import Block, Break, If, LoopExit, While, block_ends_path
from .ed9_nodes import DebugInt, PopN, Register, SyscallCall
from .nodes import BinaryOperation, Const, Global, Let, Local, Param, Return, Set, UnaryOperation

# POP's byte count is one byte: the compiler pops more as POP of this many, then the rest
POP_MAX_BYTES = OperandFormat.integer_range(OperandType.UInt8).stop - 1

# HLIL's operators as ED9's opcodes; ED9 has no BIT_XOR, SHL or SHR
BINARY_OPCODES = {
    operators.BinaryOp.ADD      : ED9Opcode.ADD,
    operators.BinaryOp.SUB      : ED9Opcode.SUB,
    operators.BinaryOp.MUL      : ED9Opcode.MUL,
    operators.BinaryOp.DIV      : ED9Opcode.DIV,
    operators.BinaryOp.MOD      : ED9Opcode.MOD,
    operators.BinaryOp.EQ       : ED9Opcode.EQ,
    operators.BinaryOp.NE       : ED9Opcode.NE,
    operators.BinaryOp.LT       : ED9Opcode.LT,
    operators.BinaryOp.LE       : ED9Opcode.LE,
    operators.BinaryOp.GT       : ED9Opcode.GT,
    operators.BinaryOp.GE       : ED9Opcode.GE,
    operators.BinaryOp.AND      : ED9Opcode.LOGICAL_AND,
    operators.BinaryOp.OR       : ED9Opcode.LOGICAL_OR,
    operators.BinaryOp.BIT_AND  : ED9Opcode.BITWISE_AND,
    operators.BinaryOp.BIT_OR   : ED9Opcode.BITWISE_OR,
}
UNARY_OPCODES = {
    operators.UnaryOp.NEG       : ED9Opcode.NEG,
    operators.UnaryOp.BIT_NOT   : ED9Opcode.NOT,
    operators.UnaryOp.NOT       : ED9Opcode.EZ,     # 1 when the value is 0
}
# A constant's kind, its value's type, as the push opcode: the first kind the value is an instance of, RawInt before the
# int it subclasses; any other kind of int, float or str takes its base's push
PUSH_OPCODES = (
    (RawInt, ED9Opcode.PUSH_RAW),
    (int,    ED9Opcode.PUSH_INT),
    (float,  ED9Opcode.PUSH_FLOAT),
    (str,    ED9Opcode.PUSH_STR),
)


class Sink(Protocol):
    def at(self, site):
        """The opcodes that follow are the node made at site's"""

    def new_label(self) -> str:
        """A label name not used yet"""

    def label(self, name: str):
        """Place label name here"""

    def emit(self, opcode: ED9Opcode, *operands):
        """One opcode, its operands as its DSL opcode function takes them"""


class Loop(NamedTuple):
    """A While being lowered: its head's label and its end's, and where its block starts in Lowering.block_depths"""

    head: str
    end: str
    block: int


class Lowering:
    """One HLIL body's statements as opcodes into a sink. stack_depth counts the slots in use (the parameters, the
    locals, the values in flight): a variable's LOAD_STACK and POP_TO offsets follow from it"""

    def __init__(self, sink: Sink, param_count: int, build: Build):
        """build: the one that made the statements, which locates an operator ED9 lacks at its line"""
        self.sink = sink
        self.param_count = param_count
        self.build = build
        self.stack_depth = param_count
        self.local_slots: dict[str, int] = {}
        self.block_depths: list[int] = []   # the stack depth where each block being lowered started, outermost first
        self.loops: list[Loop] = []         # the Whiles being lowered, outermost first

    def run(self, statements: list[BodyStatement]):
        for statement in statements:
            self.lower_statement(statement)

    def lower_statement(self, node: BodyStatement):
        sink = self.sink
        sink.at(node.site)
        match node:
            case Call():
                self.lower_call(node)

            case Set():
                self.push_operand(node.value, node.site)
                self.store(node.target)

            case Let():
                self.lower_let(node)

            case Return():
                self.lower_return(node)

            case PopN():
                self.push_args(node.values, node.site)
                sink.emit(ED9Opcode.POPN, len(node.values))
                self.stack_depth -= len(node.values)

            case DebugInt():
                sink.emit(ED9Opcode.DEBUG_INT, node.value)

            case If():
                self.lower_if(node)

            case While():
                self.lower_while(node)

            case LoopExit():
                self.lower_loop_exit(node)

    def lower_if(self, node: If):
        """Each arm: the statements made before its test, its condition, a jump past the arm when it is 0, its block,
        then a jump to the If's end unless the block ends its path or no arm follows; the else block after the last.
        The locals declared before an arm's test live through the arm: popped before the jump to the end and past the
        arm, at one POP when no arm follows"""
        sink = self.sink
        end = None
        for index, arm in enumerate(node.arms):
            following = sink.new_label()
            depth = self.stack_depth
            self.block_depths.append(depth)
            self.run(arm.before)
            declared = self.stack_depth - depth
            self.jump_if_zero(arm.condition, following, arm.site)
            self.lower_block(arm.block)
            self.block_depths.pop()
            last = index == len(node.arms) - 1 and node.else_block is None
            if not last and not block_ends_path(arm.block):
                end = end or sink.new_label()
                sink.at(arm.site)
                self.pop(declared)
                sink.emit(ED9Opcode.JMP, end)

            sink.label(following)
            self.stack_depth = depth + declared
            self.pop(declared)

        if node.else_block is not None:
            self.lower_block(node.else_block)

        if end is not None:
            sink.label(end)

    def lower_while(self, node: While):
        """The head: the statements made before its test, its condition, a jump past the loop when it is 0, its block,
        then a jump to the head unless the block ends its path. The locals declared before the test live for one
        pass: popped before the jump to the head and on the way out"""
        sink = self.sink
        depth = self.stack_depth
        loop = Loop(sink.new_label(), sink.new_label(), len(self.block_depths))
        sink.label(loop.head)
        self.block_depths.append(depth)
        self.loops.append(loop)
        self.run(node.before)
        declared = self.stack_depth - depth
        way_out = sink.new_label() if declared else loop.end
        self.jump_if_zero(node.condition, way_out, node.site)
        self.lower_block(node.block)
        self.loops.pop()
        self.block_depths.pop()
        if not block_ends_path(node.block):
            sink.at(node.site)
            self.pop(declared)
            sink.emit(ED9Opcode.JMP, loop.head)

        if declared:
            sink.label(way_out)
            self.stack_depth = depth + declared
            self.pop(declared)

        sink.label(loop.end)

    def lower_loop_exit(self, node: LoopExit):
        """A POP of each left block's locals, the loop's own block first (as the compiler writes it), then a jump past
        the innermost loop (Break) or to its head (Continue)"""
        loop = self.loops[-1]
        for block_start, next_start in pairwise([*self.block_depths[loop.block:], self.stack_depth]):
            self.pop(next_start - block_start)

        self.sink.emit(ED9Opcode.JMP, loop.end if isinstance(node, Break) else loop.head)

    def jump_if_zero(self, condition, target: str, site):
        self.push_operand(condition, site)
        self.sink.emit(ED9Opcode.POP_JMP_ZERO, target)
        self.stack_depth -= 1

    def lower_block(self, block: Block):
        """block's statements, then a pop of the locals it declared unless its path ended; the code after it starts at
        the depth before it either way"""
        depth = self.stack_depth
        self.block_depths.append(depth)
        for statement in block:
            self.lower_statement(statement)

        self.block_depths.pop()
        if not block_ends_path(block):
            self.pop(self.stack_depth - depth)

        self.stack_depth = depth

    def lower_let(self, node: Let):
        self.local_slots[node.local.name] = self.stack_depth
        self.push(ED9Opcode.PUSH_RAW, RawInt(0))
        if node.value is not None:
            self.push_operand(node.value, node.site)
            self.store(node.local)

    def lower_return(self, node: Return):
        if node.value is None:
            self.push(ED9Opcode.PUSH_RAW, RawInt(0))    # the compiler's return value
        else:
            self.push_operand(node.value, node.site)

        self.sink.emit(ED9Opcode.SET_REG, RESULT_REGISTER)
        self.stack_depth -= 1       # SET_REG popped the value
        self.discard_frame()
        self.sink.emit(ED9Opcode.RETURN)

    def discard_frame(self):
        """Pop every slot still in use: the locals and the parameters"""
        self.pop(self.stack_depth)

    def push_operand(self, node, site):
        """node's value pushed, a leaf at site (its user's line), then site again for the user's own opcodes"""
        self.sink.at(site)
        self.push_value(node)
        self.sink.at(site)

    def push_value(self, node):
        match node:
            case Const():
                opcode = next(opcode for kind, opcode in PUSH_OPCODES if isinstance(node.value, kind))
                self.push(opcode, node.value)

            case Param() | Local():
                self.push(ED9Opcode.LOAD_STACK, self.stack_offset(node))

            case Register():
                self.push(ED9Opcode.GET_REG, node.index)

            case Global():
                self.push(ED9Opcode.LOAD_GLOBAL, node.name)

            case BinaryOperation():
                opcode = BINARY_OPCODES.get(node.op)
                if opcode is None:
                    raise self.build.fail_at(node.site, f'{node!r}: the ED9 VM has no {node.op.name} operation')

                self.push_operand(node.lhs, node.site)
                self.push_operand(node.rhs, node.site)
                self.sink.emit(opcode)
                self.stack_depth -= 1

            case UnaryOperation():
                self.push_operand(node.operand, node.site)
                self.sink.emit(UNARY_OPCODES[node.op])

            case Call():
                self.lower_call(node)
                self.push(ED9Opcode.GET_REG, RESULT_REGISTER)

    def lower_call(self, node: Call):
        sink = self.sink
        sink.at(node.site)
        match node:
            case LocalCall():
                return_label = sink.new_label()
                sink.emit(ED9Opcode.PUSH_CURRENT_FUNC_ID)
                sink.emit(ED9Opcode.PUSH_RET_ADDR, return_label)
                self.stack_depth += LOCAL_SETUP_SLOTS
                self.push_args(node.args, node.site)
                sink.emit(ED9Opcode.CALL, node.function)
                sink.label(return_label)
                self.stack_depth -= LOCAL_SETUP_SLOTS + len(node.args)

            case ScriptCall():
                return_label = sink.new_label()
                sink.emit(ED9Opcode.PUSH_CALLER_FRAME, return_label)
                self.stack_depth += CALLER_FRAME_SLOTS
                self.push_args(node.args, node.site)
                sink.emit(ED9Opcode.CALL_SCRIPT, node.module, node.name, len(node.args))
                sink.label(return_label)
                self.stack_depth -= CALLER_FRAME_SLOTS + len(node.args)

            case SyscallCall():
                self.push_args(node.args, node.site)
                sink.emit(ED9Opcode.SYSCALL, node.subsystem, node.cmd, len(node.args))
                self.pop(len(node.args))  # a syscall reads its arguments without popping them

    def push_args(self, values: tuple, site):
        """The last first: the first argument ends on top"""
        for value in reversed(values):
            self.push_operand(value, site)

    def push(self, opcode: ED9Opcode, *operands):
        """An opcode pushing one value"""
        self.sink.emit(opcode, *operands)
        self.stack_depth += 1

    def pop(self, slots: int):
        size = slots * WORD_SIZE
        while size > POP_MAX_BYTES:
            self.sink.emit(ED9Opcode.POP, POP_MAX_BYTES)
            size -= POP_MAX_BYTES

        if size:
            self.sink.emit(ED9Opcode.POP, size)

        self.stack_depth -= slots

    def store(self, target):
        """Pop the value on top into target"""
        self.stack_depth -= 1     # the value is consumed: POP_TO's offset counts the stack after the pop
        match target:
            case Global():
                self.sink.emit(ED9Opcode.SET_GLOBAL, target.name)

            case Register():
                self.sink.emit(ED9Opcode.SET_REG, target.index)

            case Param() | Local():
                self.sink.emit(ED9Opcode.POP_TO, self.stack_offset(target))

    def stack_offset(self, variable: Param | Local) -> int:
        """Bytes from the stack's top to its slot; slots count from the frame's bottom, the last parameter's is 0"""
        slot = (self.param_count - variable.position if isinstance(variable, Param)
                else self.local_slots[variable.name])
        return (slot - self.stack_depth) * WORD_SIZE
