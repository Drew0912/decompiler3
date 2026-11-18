"""The HLIL DSL's lowering (docs/dsl/HLIL_DSL.md, Recompile Path): an HLIL body's statements as the LLIL opcodes the
compiler writes for them, handed to a sink one at a time - at compile time the writer's opcode functions
(opcode_sink.py). It starts with the stack holding exactly the parameters (slot 0 the last); a local's slot is where
its Let pushed it; arguments are pushed last first; a call's result is read from REGS[0]. Each opcode is at the line
of the node it lowers, a leaf's at its user's"""

from typing import Protocol

from assembler import OperandFormat, OperandType
from ...assembler import ED9Opcode
from ...assembler.vm import CALLER_FRAME_SLOTS, LOCAL_SETUP_SLOTS, RESULT_REGISTER, WORD_SIZE
from ...structs.scp_types import RawInt
from .nodes import (BinaryOp, Call, Const, DebugInt, Global, Let, Local, LocalCall, Param, PopN, Register, Return,
                    ScriptCall, Set, Statement, SyscallCall, UnaryOp)

# POP's byte count is one byte: the compiler pops more as POP of this many, then the rest
POP_MAX_BYTES = OperandFormat.integer_range(OperandType.UInt8).stop - 1


class Sink(Protocol):
    def at(self, site):
        """The opcodes that follow are the node made at site's"""

    def new_label(self) -> str:
        """A label name not used yet"""

    def label(self, name: str):
        """Place label name here"""

    def emit(self, opcode: ED9Opcode, *operands):
        """One opcode, its operands as its DSL opcode function takes them"""


class Lowering:
    def __init__(self, sink: Sink, param_count: int):
        self.sink = sink
        self.param_count = param_count
        self.sp = param_count                       # slots in use: the parameters, the locals, the values in flight
        self.local_slots: dict[str, int] = {}

    def run(self, statements: list[Statement | Call]):
        for statement in statements:
            self.statement(statement)

    def statement(self, node: Statement | Call):
        sink = self.sink
        sink.at(node.site)
        match node:
            case Call():
                self.call(node)

            case Set():
                self.operand(node.value, node.site)
                self.store(node.target)

            case Let():
                self.local_slots[node.local.name] = self.sp
                self.push(ED9Opcode.PUSH_RAW, RawInt(0))
                if node.value is not None:
                    self.operand(node.value, node.site)
                    self.store(node.local)

            case Return():
                self.operand(node.value, node.site)
                sink.emit(ED9Opcode.SET_REG, RESULT_REGISTER)
                self.sp -= 1
                self.pop(self.sp)
                sink.emit(ED9Opcode.RETURN)

            case PopN():
                self.push_args(node.values, node.site)
                sink.emit(ED9Opcode.POPN, len(node.values))
                self.sp -= len(node.values)

            case DebugInt():
                sink.emit(ED9Opcode.DEBUG_INT, node.value)

    def operand(self, node, site):
        """node's value pushed, a leaf at site (its user's line), then site again for the user's own opcodes"""
        self.sink.at(site)
        self.expr(node)
        self.sink.at(site)

    def expr(self, node):
        match node:
            case Const():
                self.push(node.opcode, node.value)

            case Param() | Local():
                self.push(ED9Opcode.LOAD_STACK, self.stack_offset(node))

            case Register():
                self.push(ED9Opcode.GET_REG, node.index)

            case Global():
                self.push(ED9Opcode.LOAD_GLOBAL, node.name)

            case BinaryOp():
                self.operand(node.lhs, node.site)
                self.operand(node.rhs, node.site)
                self.sink.emit(node.opcode)
                self.sp -= 1

            case UnaryOp():
                self.operand(node.operand, node.site)
                self.sink.emit(node.opcode)

            case Call():
                self.call(node)
                self.push(ED9Opcode.GET_REG, RESULT_REGISTER)

    def call(self, node: Call):
        sink = self.sink
        sink.at(node.site)
        match node:
            case LocalCall():
                return_label = sink.new_label()
                sink.emit(ED9Opcode.PUSH_CURRENT_FUNC_ID)
                sink.emit(ED9Opcode.PUSH_RET_ADDR, return_label)
                self.sp += LOCAL_SETUP_SLOTS
                self.push_args(node.args, node.site)
                sink.emit(ED9Opcode.CALL, node.function)
                sink.label(return_label)
                self.sp -= LOCAL_SETUP_SLOTS + len(node.args)

            case ScriptCall():
                return_label = sink.new_label()
                sink.emit(ED9Opcode.PUSH_CALLER_FRAME, return_label)
                self.sp += CALLER_FRAME_SLOTS
                self.push_args(node.args, node.site)
                sink.emit(ED9Opcode.CALL_SCRIPT, node.module, node.name, len(node.args))
                sink.label(return_label)
                self.sp -= CALLER_FRAME_SLOTS + len(node.args)

            case SyscallCall():
                self.push_args(node.args, node.site)
                sink.emit(ED9Opcode.SYSCALL, node.subsystem, node.cmd, len(node.args))
                self.pop(len(node.args))  # a syscall reads its arguments without popping them

    def push_args(self, values: tuple, site):
        """The last first: the first argument ends on top"""
        for value in reversed(values):
            self.operand(value, site)

    def push(self, opcode: ED9Opcode, *operands):
        """An opcode pushing one value"""
        self.sink.emit(opcode, *operands)
        self.sp += 1

    def pop(self, slots: int):
        size = slots * WORD_SIZE
        while size > POP_MAX_BYTES:
            self.sink.emit(ED9Opcode.POP, POP_MAX_BYTES)
            size -= POP_MAX_BYTES

        if size:
            self.sink.emit(ED9Opcode.POP, size)

        self.sp -= slots

    def store(self, target):
        """Pop the value on top into target"""
        self.sp -= 1     # POP_TO's offset counts after the pop
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
        return (slot - self.sp) * WORD_SIZE
