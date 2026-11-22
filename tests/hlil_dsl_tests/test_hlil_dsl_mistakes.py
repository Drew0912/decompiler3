#!/usr/bin/env python3
"""The HLIL DSL's mistakes (docs/dsl/HLIL_DSL.md, Python traps): each plausible one raises at its line, naming the fix -
in the nodes, the build's checks of the statements, the source check, the writer's guards; a DSL error the body catches
still ends the build"""

import contextlib
import functools
from pathlib import Path
import re
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.writer.hlil_dsl.build import HLILError
from falcom.ed9.writer.scp_hlil_dsl_helper import *
from falcom.ed9.writer.scp_writer_helper import *
from tests.shared.hlil_dsl_test_utils import *
from tests.shared.scp_writer_test_utils import at, marked_line


def raw_wait(arg1: Value32, arg2: Value32):
    """A library function as generated before @library_function: its name is its raw body"""
    POP(2 * WORD_SIZE)  # line: raw library opcode
    RETURN()


def staged_speed():
    """A helper keeping a call in a Python variable: the source check reads it when the body runs it"""
    speed = AdjustSpeed(1)  # line: staged helper
    chr_set_animeclip_speed(65534, speed, 0)


def crossing_else(condition):
    """A helper giving an If its Else after the next statement (Codex's): the Else would run before that statement.
    Its blocks hold no call, which the source check would find kept in chain"""
    chain = If(condition, [Set(REGS[1], 1)])
    Set(REGS[2], 2)
    chain.Else([Set(REGS[3], 3)])


def contiguous_else(condition):
    """crossing_else's twin with the Else before the next statement: one chain, then the statement"""
    chain = If(condition, [Set(REGS[1], 1)])
    chain.Else([Set(REGS[3], 3)])
    Set(REGS[2], 2)


def block_before_condition():
    """A helper making a block before its condition: the condition runs first"""
    block = [Set(REGS[1], 1)]
    If(REGS[2] == 1, block)


def block_inside_condition(arg1, arg2):
    """A helper making a block between its condition's operations (Fable's): the condition runs first"""
    difference = arg2 - arg1
    block = [Set(REGS[1], 1)]
    If(difference > 0, block)


@macro
def computed(value):
    """A macro making a statement besides the value it returns"""
    Set(REGS[3], 3)
    return value + 1


@macro
def tested_late(value):
    """A condition macro making its test before its own statement, which runs before the test"""
    test = value > 0
    Set(REGS[6], 6)
    return test


@macro
def returning_early(value):
    """A condition macro whose own statement ends the path before the test"""
    Return(5)
    return value


@macro
def noted(value):
    """A macro making a statement and returning nothing"""
    Set(REGS[5], value)


@macro
def counted(value):
    """A macro making a statement, returning value as it is"""
    Set(REGS[2], 9)
    return value


@macro
def set_then(register, value):
    """A macro setting register to 9, returning value as it is"""
    Set(register, 9)
    return value


@macro
def pair(value):
    """A macro returning a tuple after making a statement"""
    Set(REGS[3], 1)
    return value, value


@macro
def number():
    """A macro returning a Python number after making a statement"""
    Set(REGS[2], 2)
    return 5


@macro
def empty_after_noting():
    """A macro returning an empty list after making a statement"""
    Set(REGS[3], 1)
    return []


@macro
def carrying_an_unmarked(value):
    """A macro calling an unmarked function inside an expression: that function's statement is not the macro's"""
    Set(REGS[1], plain_counted(value))  # line: inside a macro


def counted_then_late(value):
    """Unmarked, called on a line of its own: a macro's value kept, a statement made, then the value tested"""
    kept = counted(value)
    Set(REGS[9], 1)
    While(kept, [Set(value, value - 1)])


def counted_twice(value):
    """Unmarked, called on a line of its own: a macro's value kept and used twice"""
    kept = counted(value)
    Set(REGS[1], kept)
    Set(REGS[2], kept)


def plain_note(value):
    """Unmarked: makes a statement and returns nothing"""
    Set(REGS[3], value)


def plain_counted(value):
    """Unmarked: makes a statement, returns value as it is"""
    Set(REGS[2], 9)
    return value


def plain_pair(value):
    """Unmarked: makes a statement, returns two values"""
    Set(REGS[3], 1)
    return value, value


def plain_generated():
    """Yields one statement and makes another"""
    yield Set(REGS[1], 1)
    Set(REGS[2], 2)


class Box:
    """Holds a value on an attribute"""
    value = None


def attribute_store():
    """Unmarked, called on a line of its own: an unmarked function's value stored on an attribute"""
    Box.value = plain_note(7)  # line: stored


def unpacking(value):
    """Unmarked, called on a line of its own: an unmarked function's value unpacked"""
    first, second = plain_pair(value)  # line: unpacking


def when(condition, block):
    """The script's own wrapper, unmarked: returns the If it makes"""
    return If(condition, block)


def repeat(times, block):
    """A wrapper making a statement before the While holding the block it was given"""
    counter = Local('counter')
    Let(counter, 0)
    While(counter < times, [*block, Set(counter, counter + 1)])


def chained_assignment(value):
    """Unmarked, called on a line of its own: an unmarked function's value kept in two variables at once"""
    first = second = plain_counted(value)  # line: chained assignment
    return first, second


def plain_counting():
    """A generator making a statement as it is iterated"""
    Set(REGS[1], 1)
    yield 1


def loop_over_generator():
    """Unmarked, called on a line of its own: a loop over a generator making statements"""
    for _ in plain_counting():  # line: over a generator
        pass


def nested_listed_out_of_order(value):
    """An If made before a statement, then listed after it"""
    inner = If(value, [Set(REGS[5], 5)])
    last = Set(REGS[1], 1)
    If(value, [last, inner])


def second_arm_made_first(value):
    """An If's else block made before its first block"""
    otherwise = [Set(REGS[2], 2)]
    If(value, [Set(REGS[1], 1)]).Else(otherwise)


@macro
def repeating(times, block):
    """A macro making a statement before the While holding the block it was given"""
    counter = Local('counter')
    Let(counter, 0)
    While(counter < times, [*block, Set(counter, counter + 1)])


def block_kept_before_condition(value):
    """A block kept in a variable, made before its If's condition"""
    block = [Set(REGS[1], 1)]
    If(value == 1, block)



class MistakeTestCase(HLILTestCase):
    def assert_raises_at(self, register, marker: str, function: str, text: str, error: type = HLILError):
        """Compiling register's script raises error at the line marked marker, in function, its message starting
        with text"""
        with self.assertRaisesRegex(error, f'^{at(__file__, marker)}{function}: {re.escape(text)}'):
            self.compiled(register)


class TestNodeUse(MistakeTestCase):
    def test_a_node_used_twice(self):
        def register(scena):
            @scena.HLILCode()
            def Func(arg1: Value32, arg2: Value32):
                value = arg1 + 1
                Set(arg1, value)
                Set(arg2, value)  # line: second use
                Return()

        self.assert_raises_at(register, 'second use', 'Func', '(arg1 ADD 1) is used twice')

    def test_a_statement_used_as_a_value(self):
        def register(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Set(arg1, Return())  # line: statement as value
                Return()

        self.assert_raises_at(register, 'statement as value', 'Func', 'Return(...) is a statement, not a value')

    def test_a_value_never_used(self):
        def register(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                arg1 + 1  # line: unused
                Return()

        self.assert_raises_at(register, 'unused', 'Func', '(arg1 ADD 1) is computed and never used')

    def test_an_operator_the_vm_lacks(self):
        """HLIL has ^, << and >>; ED9 has none of them"""
        def xor(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Set(arg1, arg1 ^ 4)  # line: xor
                Return()

        def shift_left(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Set(arg1, arg1 << 1)  # line: shift left
                Return()

        def shift_right(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Set(arg1, 1 >> arg1)  # line: shift right
                Return()

        for register, marker, text in ((xor, 'xor', '(arg1 BIT_XOR 4)'), (shift_left, 'shift left', '(arg1 SHL 1)'),
                                       (shift_right, 'shift right', '(1 SHR arg1)')):
            with self.subTest(marker):
                self.assert_raises_at(register, marker, 'Func', f'{text}: the ED9 VM has no {text.split()[1]} '
                                                                'operation')

    def test_a_call_made_before_a_statement_and_used_after_it(self):
        """Kept in a list, which the source check doesn't see: it would run after the statement between"""
        kept = []

        def register(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func():
                kept.append(AdjustSpeed(1))  # line: made early
                chr_wait_animeclip(65534, 0)
                chr_wait_animeclip(65534, kept.pop())
                Return()

        self.assert_raises_at(register, 'made early', 'Func', 'AdjustSpeed(...) is made here but used by '
                                                              'chr_wait_animeclip(...), after chr_wait_animeclip(...)')

    def test_python_tests_a_node(self):
        """if, and / or / not and a chained comparison all ask for a truth value"""
        def register(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Set(arg1, 0 < arg1 < 5)  # line: chained
                Return()

        self.assert_raises_at(register, 'chained', 'Func', '(arg1 GT 0) has no truth value')

    def test_a_bool_or_none(self):
        for value in (True, None):
            with self.subTest(value=value):
                def register(scena):
                    @scena.HLILCode()
                    def Func(arg1: Value32):
                        Set(arg1, value)  # line: no DSL value
                        Return()

                self.assert_raises_at(register, 'no DSL value', 'Func', f'{value!r} is not a DSL value')

    def test_a_node_in_text(self):
        """An f-string or %-formatting of a game value would compile the node's description as fixed text"""
        def f_string(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func(arg1: Value32):
                chr_change_skin(65534, f'mon{arg1}', 1)  # line: f-string
                Return()

        def percent(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func(arg1: Value32):
                chr_change_skin(65534, 'mon%s' % arg1, 1)  # line: percent
                Return()

        for register, marker in ((f_string, 'f-string'), (percent, 'percent')):
            with self.subTest(marker=marker):
                self.assert_raises_at(register, marker, 'Func', 'arg1 is a game value; text is fixed when the '
                                                                'script compiles')

    def test_a_script_function_not_called(self):
        def register(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Set(arg1, script.btlcom.AniBtlMove)  # line: not called
                Return()

        self.assert_raises_at(register, 'not called', 'Func', 'script.btlcom.AniBtlMove (ScriptFunction) is not a DSL '
                                                              'value')

    def test_a_literal_argument_is_at_its_call_line(self):
        """Not at the line of the call argument lowered before it (the arguments go last first)"""
        def register(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func():
                chr_change_skin(65534, 'mon\0',  # line: literal's call
                                map_obj_get_animeclip_frame_length('', 0))
                Return()

        self.assert_raises_at(register, "literal's call", 'Func', 'PUSH_STR string', error=ValueError)

    def test_a_missing_comma_and_a_wrong_target(self):
        def missing_comma(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Syscall(1, 2, arg1 (arg1))  # line: missing comma
                Return()

        def wrong_target(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Set(5, arg1)  # line: wrong target
                Return()

        self.assert_raises_at(missing_comma, 'missing comma', 'Func', 'arg1(...): missing comma?')
        self.assert_raises_at(wrong_target, 'wrong target', 'Func', "Set's target is a parameter, a local, this.x "
                                                                    'or REGS[n], not 5')

    def test_an_assignment_to_this_or_a_register(self):
        def to_this(scena):
            @scena.HLILCode()
            def Func():
                this.flag = 1  # line: this assignment
                Return()

        def to_register(scena):
            @scena.HLILCode()
            def Func():
                REGS[0] = 1  # line: register assignment
                Return()

        def bad_register(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Set(arg1, REGS[arg1])  # line: register number
                Return()

        self.assert_raises_at(to_this, 'this assignment', 'Func', 'this.flag = ... sets nothing in the game: write '
                                                                  'Set(this.flag, value)')
        self.assert_raises_at(to_register, 'register assignment', 'Func', 'REGS[0] = ... sets nothing in the game')
        self.assert_raises_at(bad_register, 'register number', 'Func', 'REGS[n] takes a register number 0..15, '
                                                                       'not arg1')


class TestNodesAcrossBodies(MistakeTestCase):
    def test_a_parameter_of_another_body(self):
        """A helper keeping a value between functions: the error points at a global"""
        kept = []

        def register(scena):
            use_library(scena)

            @scena.HLILCode()
            def First(arg1: Value32):
                kept.append(arg1)
                Return()

            @scena.HLILCode()
            def Second(arg1: Value32):
                chr_wait_animeclip(kept[0], 0)  # line: other parameter
                Return()

        self.assert_raises_at(register, 'other parameter', 'Second', "arg1 belongs to First's body; to keep a value "
                                                                     'between functions, store it in a global')

    def test_a_value_from_a_finished_body(self):
        """An operation of First, kept and used by Second, would run again there"""
        kept = []

        def register(scena):
            use_library(scena)

            @scena.HLILCode()
            def First():
                value = REGS[2] + 1
                Set(REGS[1], value)
                kept.append(value)
                Return()

            @scena.HLILCode()
            def Second():
                chr_wait_animeclip(kept[0], 0)  # line: finished body
                Return()

        self.assert_raises_at(register, 'finished body', 'Second', '(REGS[2] ADD 1) was made in another HLIL body')

    def test_a_statement_kept_in_a_python_list(self):
        """A statement kept in a list nothing takes as a block, to use in another body: refused where it is made"""
        kept = []

        def register(scena):
            use_library(scena)

            @scena.HLILCode()
            def First():
                kept.append(AdjustSpeed(1))  # line: kept in a list
                Return()

        line = marked_line(__file__, 'kept in a list')
        self.assert_raises_at(register, 'kept in a list', 'First', f'AdjustSpeed(...) is written inside an expression '
                                                                    f'(line {line}) and no block took it: a statement '
                                                                    "stands on a line of its own or in a block's list")

    def test_a_node_made_outside_a_body(self):
        """At module level or in a helper's default value: no build to belong to"""
        with self.assertRaisesRegex(HLILError, r'^an operation \(ADD\) builds an HLIL node: it is written only in an '
                                               r'HLIL body'):
            Int(1) + 2

        with self.assertRaisesRegex(HLILError, r'^Set\(\.\.\.\) builds an HLIL node'):
            def helper(statement=Set(this.flag, 1)):
                pass


class TestStatements(MistakeTestCase):
    def test_calls_with_the_wrong_arguments(self):
        """A local call passes every parameter, by position: a local CALL ignores defaults"""
        def one_argument(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func():
                chr_wait_animeclip(65534)  # line: one argument
                Return()

        def extra_argument(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func():
                chr_wait_animeclip(65534, 0, 1)  # line: extra argument
                Return()

        def default_left_out(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func():
                chr_set_animeclip_speed(65534, 1.0)  # line: default left out
                Return()

        def keyword(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func():
                chr_wait_animeclip(65534, arg2=0)  # line: keyword
                Return()

        cases = ((one_argument, 'one argument', 'chr_wait_animeclip takes 2 arguments, 1 given'),
                 (extra_argument, 'extra argument', 'chr_wait_animeclip takes 2 arguments, 3 given'),
                 (default_left_out, 'default left out', 'chr_set_animeclip_speed takes 3 arguments, 2 given'),
                 (keyword, 'keyword', 'chr_wait_animeclip(...) takes its arguments by position (the VM passes them '
                                      'so), not arg2='))
        for register, marker, text in cases:
            with self.subTest(case=marker):
                self.assert_raises_at(register, marker, 'Func', text)

    def test_a_library_function_not_imported(self):
        """CALL finds no function of that name, at the HLIL line"""
        def register(scena):
            @scena.HLILCode()
            def Func():
                chr_wait_animeclip(65534, 0)  # line: not imported
                Return()

        self.assert_raises_at(register, 'not imported', 'Func', 'CALL(chr_wait_animeclip): no function of that name '
                                                                'in this script', error=TypeError)

    def test_the_end_of_the_body(self):
        def no_return(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func():
                chr_wait_animeclip(65534, 0)  # line: no return

        def after_return(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func():
                Return()
                chr_wait_animeclip(65534, 0)  # line: after return

        self.assert_raises_at(no_return, 'no return', 'Func', 'the body does not end with Return(...)')
        self.assert_raises_at(after_return, 'after return', 'Func', 'a statement after Return(...)')

    def test_locals_declared_once_before_use(self):
        def set_before_let(scena):
            @scena.HLILCode()
            def Func():
                x = Local('x')
                Set(x, 1)  # line: set before let
                Return()

        def read_before_let(scena):
            @scena.HLILCode()
            def Func():
                x = Local('x')
                Let(x, x + 1)  # line: read before let
                Return()

        def second_let(scena):
            @scena.HLILCode()
            def Func():
                x = Local('x')
                Let(x)
                Let(x, 2)  # line: second let
                Return()

        self.assert_raises_at(set_before_let, 'set before let', 'Func', 'Set(x, ...) before Let(x)')
        self.assert_raises_at(read_before_let, 'read before let', 'Func', 'local x is read before Let(x, ...)')
        self.assert_raises_at(second_let, 'second let', 'Func', 'a second Let(x, ...)')

    def test_a_caught_dsl_error_still_ends_the_build(self):
        """However it was caught - a bool, a truth test, an LLIL opcode: the first is raised after the body"""
        def register(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                for mistake in (lambda: Set(arg1, True), lambda: bool(arg1 > 0), lambda: PUSH_INT(1)):
                    try:
                        mistake()  # line: caught
                    except HLILError:
                        pass

                Return()

        self.assert_raises_at(register, 'caught', 'Func', 'True is not a DSL value')


class TestControlFlow(MistakeTestCase):
    """If's blocks and chain, the creation order across its arms, the paths, the locals of a block"""

    def test_a_block_and_its_elements(self):
        """A bad element is reported at its own line when it is a node, else at the If's; a list changed after the If
        took it, at its arm's"""
        kept = []

        def not_a_list(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, Return())  # line: not a list
                Return()

        def a_value(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [
                    arg1 == 5,  # line: a value
                ])
                Return()

        def missing_comma(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [  # line: the if
                    Syscall(1, 2, 3)  # line: joined
                    -arg1,
                ])
                Return()

        def a_tuple(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [(Syscall(1, 2, 3), Syscall(1, 2, 4))])  # line: tuple
                Return()

        def not_called(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [Return])  # line: block element not called
                Return()

        def two_blocks(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                kept.append([Syscall(1, 2, 3)])
                If(arg1, kept[0]).Else(kept[0])  # line: two blocks
                Return()

        def changed_after(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                block = []
                If(arg1, block)  # line: changed block
                block.append(Set(REGS[1], 5))
                Return()

        cases =((not_a_list, 'not a list', 'a block is a list of statements, [...], not Return(...)'),
                 (a_value, 'a value', '(arg1 EQ 5) in a block is not a statement: each element of [...] is a call or '
                                      'a statement (a missing comma joins two lines into one value)'),
                 (missing_comma, 'joined', '(Syscall(1, 2, ...) SUB arg1) in a block is not a statement'),
                 (a_tuple, 'tuple', '(Syscall(1, 2, ...), Syscall(1, 2, ...)) in a block is a tuple: a block holds '
                                    'statements and lists of them, [...]'),
                 (not_called, 'block element not called', 'Return in a block is not a statement: write Return(...), '
                                                          'its call'),
                 (two_blocks, 'two blocks', 'Syscall(1, 2, ...) is in two blocks (or a block is used twice)'),
                 (changed_after, 'changed block', 'a block changed after its If took it'))
        for register, marker, text in cases:
            with self.subTest(case=marker):
                self.assert_raises_at(register, marker, 'Func', text)

    def test_the_if_arguments_and_its_chain(self):
        kept = []

        def keyword(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, block=[Syscall(1, 2, 3)])  # line: if keyword
                Return()

        def third_block(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [Syscall(1, 2, 3)], [Syscall(1, 2, 4)])  # line: third block
                Return()

        def else_if_after_else(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [Syscall(1, 2, 3)]).Else([
                    Syscall(1, 2, 4),
                ]).ElseIf(arg1, [Syscall(1, 2, 5)])  # line: else if after else
                Return()

        def second_else(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [Syscall(1, 2, 3)]).Else([
                    Syscall(1, 2, 4),
                ]).Else([Syscall(1, 2, 5)])  # line: second else
                Return()

        def arm_after_use(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                kept.append(If(arg1, [Syscall(1, 2, 3)]))
                If(arg1, [kept[0]])
                kept[0].Else([Syscall(1, 2, 4)])  # line: arm after use
                Return()

        cases = ((keyword, 'if keyword', 'If takes its condition and its block by position, not block='),
                 (third_block, 'third block', 'If takes a condition and a block, If(condition, [...]); the else is '
                                              '.Else([...]) after it'),
                 (else_if_after_else, 'else if after else', '.ElseIf(...) after .Else(...), the last arm'),
                 (second_else, 'second else', '.Else(...) after .Else(...), the last arm'),
                 (arm_after_use, 'arm after use', '.Else(...) on an If already in a block'))
        for register, marker, text in cases:
            with self.subTest(case=marker):
                self.assert_raises_at(register, marker, 'Func', text)

    def test_creation_order_across_the_arms(self):
        """A helper's statement made between an If's arms, or its block made before its condition or between the
        condition's operations, would run out of the order written; the arm given before the next statement compiles"""
        def crossing(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                crossing_else(arg1)  # line: crossing helper
                Return()

        def contiguous(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                contiguous_else(arg1)
                Return()

        def early_block(scena):
            @scena.HLILCode()
            def Func():
                block_before_condition()  # line: early block
                Return()

        def block_in_condition(scena):
            @scena.HLILCode()
            def Func(arg1: Value32, arg2: Value32):
                block_inside_condition(arg1, arg2)  # line: block in condition
                Return()

        self.assert_raises_at(crossing, 'crossing helper', 'Func', "Set(REGS[2], ...) is made between an If's arms, "
                                                                   'in no block: no code runs there')
        self.compiled(contiguous)
        self.assert_raises_at(early_block, 'early block', 'Func', 'Set(REGS[1], ...) is made here but runs after '
                                                                  '(REGS[2] EQ 1), made later')
        self.assert_raises_at(block_in_condition, 'block in condition', 'Func', '((arg2 SUB arg1) GT 0) is made here '
                                                                                'but runs before Set(REGS[1], ...), '
                                                                                'made earlier')

    def test_paths_that_end(self):
        def after_an_ending_if(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [Return(1)]).Else([Return(2)])
                Syscall(1, 2, 3)  # line: after the if
                Return()

        def after_a_return_in_a_block(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [
                    Return(1),
                    Syscall(1, 2, 3),  # line: after the return
                ])
                Return()

        def an_if_without_else_last(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [Return(1)])  # line: no else
                # (the If is the body's last statement: its other path falls off the end)

        cases = ((after_an_ending_if, 'after the if', 'a statement after an If whose every arm, .Else included, ends '
                                                      'its path: it never runs'),
                 (after_a_return_in_a_block, 'after the return', 'a statement after Return(...), which ends the '
                                                                 'function'),
                 (an_if_without_else_last, 'no else', 'the body does not end with Return(...), or with an If whose '
                                                      'every arm, .Else included, ends with one'))
        for register, marker, text in cases:
            with self.subTest(case=marker):
                self.assert_raises_at(register, marker, 'Func', text)

    def test_the_locals_of_a_block(self):
        def read_after(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                x = Local('x')
                If(arg1, [Let(x, 1)])
                Syscall(1, 2, x)  # line: read after
                Return()

        def set_after(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                x = Local('x')
                If(arg1, [Let(x, 1)])
                Set(x, 2)  # line: set after
                Return()

        def read_in_the_next_arm(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                x = Local('x')
                If(arg1, [Let(x, 1)]).ElseIf(x, [  # line: next arm
                    Syscall(1, 2, 3),
                ])
                Return()

        def outer_declared_again(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                x = Local('x')
                Let(x, 1)
                If(arg1, [Let(x, 2)])  # line: declared again
                Return()

        cases = ((read_after, 'read after', 'local x is read after the block that declares it ends'),
                 (set_after, 'set after', 'Set(x, ...) after the block that declares x ends'),
                 (read_in_the_next_arm, 'next arm', 'local x is read after the block that declares it ends'),
                 (outer_declared_again, 'declared again', 'a second Let(x, ...)'))
        for register, marker, text in cases:
            with self.subTest(case=marker):
                self.assert_raises_at(register, marker, 'Func', text)


class TestLoops(MistakeTestCase):
    """While's arguments and block, Break and Continue outside a loop, the paths a loop leaves"""

    def test_the_while_arguments(self):
        def keyword(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                While(arg1, block=[Syscall(1, 2, 3)])  # line: while keyword
                Return()

        def third_block(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                While(arg1, [Syscall(1, 2, 3)], [Syscall(1, 2, 4)])  # line: while third block
                Return()

        def no_block(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                While(arg1)  # line: while no block
                Return()

        def break_argument(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                While(arg1, [
                    Break(1),  # line: break argument
                ])
                Return()

        no_else = 'While takes a condition and a block, While(condition, [...]) (the DSL has no loop else)'
        cases = ((keyword, 'while keyword', 'While takes its condition and its block by position, not block='),
                 (third_block, 'while third block', no_else),
                 (no_block, 'while no block', no_else),
                 (break_argument, 'break argument', 'Break() takes no arguments: it leaves the innermost While '
                                                    'holding it'))
        for register, marker, text in cases:
            with self.subTest(case=marker):
                self.assert_raises_at(register, marker, 'Func', text)

    def test_exits_outside_a_loop(self):
        """Checked before the paths, so a Break at the top level is named for what it is"""
        def at_the_top_level(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Break()  # line: top-level break
                Return()

        def in_an_if(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [
                    Continue(),  # line: continue in an if
                ])
                Return()

        cases = ((at_the_top_level, 'top-level break', 'Break() outside a While: it leaves the innermost While '
                                                        'holding it'),
                 (in_an_if, 'continue in an if', 'Continue() outside a While'))
        for register, marker, text in cases:
            with self.subTest(case=marker):
                self.assert_raises_at(register, marker, 'Func', text)

    def test_the_paths_a_loop_leaves(self):
        def after_a_break(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                While(arg1, [
                    Break(),
                    Syscall(1, 2, 3),  # line: after the break
                ])
                Return()

        def after_a_continue(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                While(arg1, [
                    Continue(),
                    Syscall(1, 2, 3),  # line: after the continue
                ])
                Return()

        def ending_in_a_loop(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                While(1, [  # line: last loop
                    Syscall(1, 2, 3),
                ])

        cases = ((after_a_break, 'after the break', 'a statement after Break(), which leaves the loop: it never runs'),
                 (after_a_continue, 'after the continue', "a statement after Continue(), which goes to the loop's next "
                                                          'test: it never runs'),
                 (ending_in_a_loop, 'last loop', 'the body ends with While(...), which never ends its path (the code '
                                                 'after it runs when its test is 0): end the body with Return(...)'))
        for register, marker, text in cases:
            with self.subTest(case=marker):
                self.assert_raises_at(register, marker, 'Func', text)

    def test_the_loop_block(self):
        def changed_after(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                block = []
                While(arg1, block)  # line: changed loop block
                block.append(Set(REGS[1], 5))
                Return()

        def break_not_called(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                While(arg1, [Break])  # line: break not called
                Return()

        def read_after(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                x = Local('x')
                While(arg1, [Let(x, 1)])
                Syscall(1, 2, x)  # line: read after the loop
                Return()

        def read_in_the_test(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                x = Local('x')
                While(x, [  # line: read in the test
                    Let(x, 1),
                ])
                Return()

        def test_made_early(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                test = arg1 > 0  # line: test made early
                Set(REGS[1], 1)
                While(test, [
                    Set(arg1, arg1 - 1),
                ])
                Return()

        cases = ((test_made_early, 'test made early', "(arg1 GT 0) is made here but runs after Set(REGS[1], ...), made "
                                                      "later: the While's condition is tested where the While stands: "
                                                      'make it there'),
                 (changed_after, 'changed loop block', 'a block changed after its While took it: the While holds the '
                                                       'list as it was then'),
                 (break_not_called, 'break not called', 'Break in a block is not a statement: write Break(), its '
                                                        'call'),
                 (read_after, 'read after the loop', 'local x is read after the block that declares it ends'),
                 (read_in_the_test, 'read in the test', 'local x is read before Let(x, ...)'))
        for register, marker, text in cases:
            with self.subTest(case=marker):
                self.assert_raises_at(register, marker, 'Func', text)


class TestMacroStatements(MistakeTestCase):
    """A statement no block holds where it can't stand where it was made: an unmarked function's called inside an
    expression, a statement written inside one; a macro's that can't run where its value goes: after an operand read
    before it, after its condition's test was made, ending the path before the test, with a value that can't carry it
    or used twice; a macro's statements truth-tested; a block made before what runs before it"""

    def test_what_a_macro_cannot_carry(self):
        def mid_expression(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Set(arg1, Syscall(1, 2, 3) + computed(arg1))  # line: mid expression
                Return()

        def after_a_read(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Set(REGS[4], REGS[3] + set_then(REGS[3], REGS[5]))  # line: after a read
                Return()

        def after_an_argument_read(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Syscall(1, 2, REGS[3], set_then(REGS[3], REGS[5]))  # line: after an argument read
                Return()

        def test_before_its_statement(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                While(tested_late(arg1), [  # line: test before statement
                    Set(arg1, arg1 - 1),
                ])
                Return()

        def ended_before_the_test(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                While(returning_early(arg1), [  # line: ended before the test
                    Set(arg1, arg1 - 1),
                ])
                Return()

        def a_tuple(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Set(REGS[1], pair(arg1)[0])  # line: a tuple
                Return()

        def a_number(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Set(REGS[1], number() + 1)  # line: a number
                Return()

        def used_twice(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                counted_twice(arg1)  # line: used twice
                Return()

        def used_after_a_statement(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                counted_then_late(arg1)  # line: used after a statement
                Return()

        def carrying_an_unmarked_statement(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [carrying_an_unmarked(arg1)])  # line: carrying an unmarked statement
                Return()

        def a_list_comprehension(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                [noted(value) for value in (1, 2)]  # line: a list comprehension
                Return()

        read_first = ("which this expression takes first: a macro's statements run before the whole statement holding "
                      'its value')
        cases = ((mid_expression, 'mid expression', 'Set(REGS[3], ...), made by a macro, would run before Syscall(1, '
                                                    f'2, ...), {read_first}'),
                 (after_a_read, 'after a read', f'Set(REGS[3], ...), made by a macro, would run before REGS[3], '
                                                f'{read_first}; keep REGS[3] in a Let on a line before, or call the '
                                                'macro first'),
                 (after_an_argument_read, 'after an argument read', 'Set(REGS[3], ...), made by a macro, would run '
                                                                    f'before REGS[3], {read_first}'),
                 (test_before_its_statement, 'test before statement', '(arg1 GT 0) is made here but runs after '
                                                                      'Set(REGS[6], ...), made later: the statements '
                                                                      "macros make for the While's condition run "
                                                                      'before its test: make its value after them'),
                 (ended_before_the_test, 'ended before the test', "Return(...), made while the While's condition is "
                                                                  'built, ends its path before the test: the '
                                                                  'condition never runs'),
                 (a_tuple, 'a tuple', 'Set(REGS[3], ...) is made in the macro pair(), called inside an expression '
                                      f"(line {marked_line(__file__, 'a tuple')}), and pair could not return it with "
                                      "its value (tuple can't carry a statement: a macro returns a DSL value, a "
                                      'statement, a list of statements or nothing)'),
                 (a_number, 'a number', 'Set(REGS[2], ...) is made in the macro number(), called inside an expression '
                                        f"(line {marked_line(__file__, 'a number')}), and number could not return it "
                                        "with its value (int can't carry a statement"),
                 (used_twice, 'used twice', "arg1, a macro's value, is used twice: the statements the macro made run "
                                            'once, where the value is used; keep a value with Let(x, value) and read '
                                            'x'),
                 (used_after_a_statement, 'used after a statement', 'Set(REGS[2], ...) is made here but runs after '
                                                                    "Set(REGS[9], ...), made later: a macro's "
                                                                    "statements for the While's condition run before "
                                                                    'its test, where the While stands: call the macro '
                                                                    'where its value is used'),
                 (carrying_an_unmarked_statement, 'carrying an unmarked statement',
                  'Set(REGS[2], ...) is made in plain_counted(), called inside an expression (line '
                  f"{marked_line(__file__, 'inside a macro')} of carrying_an_unmarked): Python gives the expression "
                  'only what plain_counted returns'),
                 (a_list_comprehension, 'a list comprehension', 'Set(REGS[5], ...) is made in the macro noted(), '
                                                                'called inside an expression (line '
                                                                f"{marked_line(__file__, 'a list comprehension')}), "
                                                                'and no block or statement took what noted returned '
                                                                'with it'))
        for register, marker, text in cases:
            with self.subTest(case=marker):
                self.assert_raises_at(register, marker, 'Func', text)

    def test_what_cannot_stand_where_made(self):
        def in_a_block(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [plain_note(1)])  # line: in a block
                Return()

        def in_a_condition(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                While(plain_counted(arg1), [  # line: in a condition
                    Set(arg1, arg1 - 1),
                ])
                Return()

        def through_a_wrapper(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                when(arg1, [plain_note(1)])  # line: through a wrapper
                Return()

        def through_a_generator(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [*plain_generated()])  # line: through a generator
                Return()

        def on_an_attribute(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                attribute_store()  # line: on an attribute
                Return()

        def unpacked(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                unpacking(arg1)  # line: unpacked
                Return()

        def in_an_expression(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [(Set(REGS[1], 1), Set(REGS[2], 2))[1]])  # line: in an expression
                Return()

        def statements_in_a_comprehension(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                [Set(REGS[register], 0) for register in (1, 2)]  # line: statements in a comprehension
                Return()

        def kept_twice(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                chained_assignment(arg1)  # line: kept twice
                Return()

        def a_generator_looped_over(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                loop_over_generator()  # line: a generator looped over
                Return()

        def mark_it(function: str, marker: str, inside: str = '') -> str:
            """The message for an unmarked function called inside an expression, in the body or in function inside
            (only there may a plain variable keep its value)"""
            where = f'{marked_line(__file__, marker)}' + (f' of {inside}' if inside else '')
            variable = f', or assign its value to one plain variable first (x = {function}(...))' if inside else ''
            return (f'is made in {function}(), called inside an expression (line {where}): Python gives the '
                    f"expression only what {function} returns, so the statement can't go where the call is written; "
                    f'mark the function (@macro above def {function}), or call it on a line of its own{variable}')

        def inside_an_expression(marker: str) -> str:
            return (f'is written inside an expression (line {marked_line(__file__, marker)}) and no block took it: a '
                    "statement stands on a line of its own or in a block's list")

        cases = ((in_a_block, 'in a block', f"Set(REGS[3], ...) {mark_it('plain_note', 'in a block')}"),
                 (in_a_condition, 'in a condition', f"Set(REGS[2], ...) {mark_it('plain_counted', 'in a condition')}"),
                 (through_a_wrapper, 'through a wrapper', 'Set(REGS[3], ...) '
                                                          f"{mark_it('plain_note', 'through a wrapper')}"),
                 (through_a_generator, 'through a generator', 'Set(REGS[2], ...) is made in the generator '
                                                              'plain_generated() (line '
                                                              f"{marked_line(__file__, 'through a generator')}): its "
                                                              "body runs as it is iterated, so its statements can't "
                                                              'go where it is called; make it a function returning a '
                                                              'list'),
                 (on_an_attribute, 'on an attribute', 'Set(REGS[3], ...) '
                                                      f"{mark_it('plain_note', 'stored', 'attribute_store')}"),
                 (unpacked, 'unpacked', f"Set(REGS[3], ...) {mark_it('plain_pair', 'unpacking', 'unpacking')}"),
                 (in_an_expression, 'in an expression',
                  f"Set(REGS[1], ...) {inside_an_expression('in an expression')}"),
                 (statements_in_a_comprehension, 'statements in a comprehension',
                  f"Set(REGS[1], ...) {inside_an_expression('statements in a comprehension')}"),
                 (kept_twice, 'kept twice',
                  f"Set(REGS[2], ...) {mark_it('plain_counted', 'chained assignment', 'chained_assignment')}"),
                 (a_generator_looped_over, 'a generator looped over',
                  'Set(REGS[1], ...) is made in the generator plain_counting() (line '
                  f"{marked_line(__file__, 'over a generator')} of loop_over_generator): its body runs as it is "
                  "iterated, so its statements can't go where it is called; make it a function returning a list"))
        for register, marker, text in cases:
            with self.subTest(case=marker):
                self.assert_raises_at(register, marker, 'Func', text)

        # In the body, where its source check refuses a call kept in a variable, the message ends with no such hint
        with self.subTest(case='no variable hint in a body'):
            with self.assertRaisesRegex(HLILError, f"{re.escape(mark_it('plain_note', 'in a block'))}$"):
                self.compiled(in_a_block)

    def test_a_macro_truth_tested(self):
        """Python's or, and, not and if test a macro's statements in place of what it returned: nothing, or a list"""
        def with_or(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [noted(1) or Set(REGS[4], 2)])  # line: or
                Return()

        def with_and(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [empty_after_noting() and Set(REGS[4], 2)])  # line: and
                Return()

        def with_not(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [Set(REGS[4], 2)] if not noted(1) else [])  # line: not
                Return()

        def with_if(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                if empty_after_noting():  # line: if
                    Set(REGS[4], 2)
                Return()

        for register, marker in ((with_or, 'or'), (with_and, 'and'), (with_not, 'not'), (with_if, 'if')):
            with self.subTest(case=marker):
                self.assert_raises_at(register, marker, 'Func', "a macro's statements have no truth value while the "
                                                                "script compiles: Python's if / while / and / or / "
                                                                'not would test them in place of what the macro '
                                                                'returned; use If(...)')

    def test_a_generator_macro(self):
        """A generator's body runs after its call returns: nothing would go with the call"""
        with self.assertRaisesRegex(HLILError, re.escape("@macro can't mark generated: a generator's body runs when it "
                                                         'is iterated, after its call returns')):
            @macro
            def generated():
                yield Set(REGS[1], 1)

    def test_a_macro_over_a_classmethod(self):
        """@macro above @classmethod gets a classmethod object, not a function: the decorators' order, at its line"""
        with self.assertRaisesRegex(HLILError, f"^{at(__file__, 'over a classmethod')}" + re.escape(
                '@macro marks a function (a def), not a classmethod: put it right above the def, below @classmethod '
                'or @staticmethod')):
            class Notes:
                @macro  # line: over a classmethod
                @classmethod
                def note(cls, value):
                    Set(REGS[3], value)

    def test_a_block_made_too_early(self):
        """A block's statement made before what runs before it: its If's condition, an earlier element of its block,
        or a statement before its If or While (a function given a block, making statements first)"""
        def before_its_condition(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                block_kept_before_condition(arg1)  # line: before its condition
                Return()

        def listed_out_of_order(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [*reversed([Set(REGS[1], 1), Set(REGS[2], 2)]), noted(3)])  # line: listed out of order
                Return()

        def given_to_a_wrapper(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                repeat(3, [Set(REGS[4], 2)])  # line: given to a wrapper
                Return()

        def given_to_a_macro_in_a_block(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                If(arg1, [repeating(3, [Set(REGS[4], 2)])])  # line: given to a macro in a block
                Return()

        def nested_out_of_order(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                nested_listed_out_of_order(arg1)  # line: nested out of order
                Return()

        def second_arm_first(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                second_arm_made_first(arg1)  # line: second arm first
                Return()

        cases = ((before_its_condition, 'before its condition', 'Set(REGS[1], ...) is made here but runs after (arg1 '
                                                                'EQ 1), made later: an If or a While runs its '
                                                                'condition before its block'),
                 (listed_out_of_order, 'listed out of order', 'Set(REGS[1], ...) is made here but runs after '
                                                              "Set(REGS[2], ...), made later: a block's list runs in "
                                                              'its written order: make its statements in that order'),
                 (given_to_a_wrapper, 'given to a wrapper', 'Set(REGS[4], ...) is made here but runs after '
                                                            'Let(counter, ...), made later: its block runs where its '
                                                            'If or While stands, after Let(counter, ...); a function '
                                                            "given a block can't make statements before the If or "
                                                            'While holding it yet'),
                 (given_to_a_macro_in_a_block, 'given to a macro in a block',
                  'Set(REGS[4], ...) is made here but runs after Let(counter, ...), made later: its block runs where '
                  "its If or While stands, after Let(counter, ...); a function given a block can't make statements "
                  'before the If or While holding it yet'),
                 (nested_out_of_order, 'nested out of order', 'Set(REGS[5], ...) is made here but runs after '
                                                              "Set(REGS[1], ...), made later: a block's list runs in "
                                                              'its written order: make its statements in that order'),
                 (second_arm_first, 'second arm first', 'Set(REGS[2], ...) is made here but runs after Set(REGS[1], '
                                                        "...), made later: an If's blocks run in their written order: "
                                                        "make each arm's block in that order"))
        for register, marker, text in cases:
            with self.subTest(case=marker):
                self.assert_raises_at(register, marker, 'Func', text)


class TestWriterGuards(MistakeTestCase):
    """What an HLIL body can't run: LLIL opcodes and labels, an old library's raw body, a body inlined"""

    def test_an_opcode_function_or_a_label(self):
        def opcode(scena):
            @scena.HLILCode()
            def Func():
                PUSH_INT(1)  # line: opcode in HLIL
                Return()

        def placed_label(scena):
            @scena.HLILCode()
            def Func():
                label('here')  # line: label in HLIL
                Return()

        self.assert_raises_at(opcode, 'opcode in HLIL', 'Func', 'PUSH_INT is an LLIL opcode, run in an HLIL body')
        self.assert_raises_at(placed_label, 'label in HLIL', 'Func', "label('here') in an HLIL body")

    def test_a_library_from_before_the_stubs(self):
        """Its raw body runs its opcodes in the build: the error names the regeneration, at the library's line"""
        def register(scena):
            @scena.CommonImports()
            def commonImports():
                return [raw_wait]

            @scena.HLILCode()
            def Func():
                raw_wait(65534, 0)
                Return()

        self.assert_raises_at(register, 'raw library opcode', 'Func', 'POP is an LLIL opcode, run in an HLIL body: an '
                                                                      'opcode function, an LLIL body called raw, or a '
                                                                      'library function from before @library_function '
                                                                      '(regenerate the library)')

    def test_a_body_inlined_in_an_hlil_body(self):
        def register(scena):
            @scena.LLILCode()
            def Other():
                RETURN()

            @scena.HLILCode()
            def Func():
                original.Other()  # line: inlined
                Return()

        self.assert_raises_at(register, 'inlined', 'Func', 'original.Other() and inline_original_func() inline a body '
                                                           'in an LLIL body only, not in an HLIL one')


class TestSourceCheck(MistakeTestCase):
    """What Python does before the DSL sees it, read in the body's source"""

    def test_a_call_kept_in_a_python_variable(self):
        """It would run where it is used, after the arguments to its right: here AdjustSpeed after chr_wait_animeclip"""
        def register(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func():
                speed = AdjustSpeed(1)  # line: call kept
                wait = chr_wait_animeclip(65534, 0)
                chr_set_animeclip_speed(65534, speed, wait)
                Return()

        self.assert_raises_at(register, 'call kept', 'Func', 'speed = AdjustSpeed(1): a call kept in a Python variable '
                                                             'runs where the variable is used')

    def test_a_call_kept_by_a_walrus_is_quoted_as_written(self):
        def register(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func():
                chr_wait_animeclip(65534, (frame := AdjustSpeed(1)))  # line: walrus
                Return()

        self.assert_raises_at(register, 'walrus', 'Func', '(frame := AdjustSpeed(1)): a call kept in a Python variable')

    def test_a_helper_and_a_wrapped_body_are_read_too(self):
        """A helper by its own rules, at its own line: a DSL call kept in a variable; the body under an ordinary
        decorator by the body's rules"""
        def helper(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func():
                staged_speed()
                Return()

        def wrapped(scena):
            @scena.HLILCode()
            @passthrough
            def Func(arg1: Value32):
                arg1 = 5  # line: wrapped rebinding
                Return(arg1)

        self.assert_raises_at(helper, 'staged helper', 'Func', 'speed = AdjustSpeed(1): a call kept in a Python '
                                                               'variable')
        self.assert_raises_at(wrapped, 'wrapped rebinding', 'Func', "arg1 = ... rebinds the Python name")

    def test_a_parameter_or_a_local_rebound(self):
        """By any binding Python has: =, for, with, ..."""
        def parameter(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                arg1 = 5  # line: parameter rebound
                Return()

        def local(scena):
            @scena.HLILCode()
            def Func():
                x = Local('x')
                Let(x)
                x = 5  # line: local rebound
                Return()

        def for_target(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                for arg1 in (7,):  # line: for target
                    pass

                Return(arg1)

        def with_target(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                with contextlib.nullcontext(9) as arg1:  # line: with target
                    pass

                Return(arg1)

        self.assert_raises_at(parameter, 'parameter rebound', 'Func', "arg1 = ... rebinds the Python name, not the "
                                                                      "game's arg1: write Set(arg1, value)")
        self.assert_raises_at(local, 'local rebound', 'Func', "x = ... rebinds the Python name, not the game's x")
        self.assert_raises_at(for_target, 'for target', 'Func', "arg1 = ... rebinds the Python name")
        self.assert_raises_at(with_target, 'with target', 'Func', "arg1 = ... rebinds the Python name")

    def test_is_on_a_parameter(self):
        """Python's identity: a node is never None"""
        def register(scena):
            @scena.HLILCode()
            def Func(arg1: Nullable32):
                if arg1 is None:  # line: is none
                    Syscall(1, 2, 99)

                Return()

        self.assert_raises_at(register, 'is none', 'Func', 'arg1 is None: is compares Python objects, never the '
                                                           "game's value (the VM has no None); compare with == or !=")

    def test_a_python_return(self):
        """Even after a Return(...): it hides what follows"""
        def register(scena):
            use_library(scena)

            @scena.HLILCode()
            def Func():
                Return()
                return  # line: python return
                chr_wait_animeclip(65534, 0)

        self.assert_raises_at(register, 'python return', 'Func', 'return stops the body here, and what follows is '
                                                                 'never built')

    def test_division_and_modulo_of_literals(self):
        """Python's / gives a Float and its % floors; the VM's DIV and MOD truncate. Other operators are Python's"""
        def division(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Set(arg1, 7 / 2)  # line: division
                Return()

        def modulo(scena):
            @scena.HLILCode()
            def Func(arg1: Value32):
                Set(arg1, -7 % 3)  # line: modulo
                Return()

        self.assert_raises_at(division, 'division', 'Func', "7 / 2: Python computes it (its / always gives a Float), "
                                                            "not the VM's DIV, which truncates; write Int(7) / 2 for "
                                                            "the VM's operation, or the value")
        self.assert_raises_at(modulo, 'modulo', 'Func', "-7 % 3: Python computes it (its % floors), not the VM's MOD, "
                                                        'which truncates; write Int(-7) % 3')


if __name__ == '__main__':
    unittest.main()
