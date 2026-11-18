"""The build an HLIL body runs under (docs/dsl/HLIL_DSL.md, Form): the nodes it makes, in creation order, where each was
made, and its first DSL error; HLILError, the DSL's own error. The nodes register here while a build is active"""

import os
import sys
from contextlib import contextmanager
from types import CodeType, FrameType
from typing import Any, Callable

# The DSL's own modules: a frame running one is neither the body nor a helper of it
DSL_FOLDER = os.path.dirname(os.path.abspath(__file__)) + os.sep


class HLILError(Exception):
    """A mistake in an HLIL body, at its line when the build can tell"""


class Build:
    """One HLIL body's run: function_name is the function the body is for; site_of() says where the statement running
    now is (opaque here), and locate(site, text) puts it in a message. With check_helper, each helper the body runs
    while it makes a node, a function between the node's creation and one of body_codes (the body's code, and its
    wrappers'), is passed to check_helper(code, its globals) on the way: a located message is its error"""

    def __init__(self, function_name: str, site_of: Callable[[], Any], locate: Callable[[Any, str], str],
                 body_codes: frozenset[int] = frozenset(),
                 check_helper: Callable[[CodeType, dict], str | None] | None = None):
        self.function_name = function_name
        self.site_of = site_of
        self.locate = locate
        self.body_codes = body_codes                    # id() of each code the body runs as itself
        self.check_helper = check_helper
        self.nodes: list = []                           # the composite nodes, in creation order
        self.first_error: HLILError | None = None       # raised again after the body, even if the body caught it

    def register(self, node):
        """A composite node joins this build, at the line making it"""
        node.build = self
        node.site = self.site_of()
        node.parent = None
        self.nodes.append(node)
        if self.check_helper is not None:
            for frame in self.helper_frames(sys._getframe(1)):
                problem = self.check_helper(frame.f_code, frame.f_globals)
                if problem is not None:
                    raise self.kept(HLILError(problem))

    def helper_frames(self, frame: FrameType) -> list[FrameType]:
        """The helpers between frame and the body: none unless the walk reaches the body"""
        helpers = []
        while frame is not None and id(frame.f_code) not in self.body_codes:
            code = frame.f_code
            # Lambdas, comprehensions and generator expressions are read with the function holding them
            if not code.co_filename.startswith(DSL_FOLDER) and not code.co_name.startswith('<'):
                helpers.append(frame)

            frame = frame.f_back

        return helpers if frame is not None else []

    def fail(self, text: str) -> HLILError:
        """The error to raise about the statement running now; the build keeps the first"""
        return self.fail_at(self.site_of(), text)

    def fail_at(self, site, text: str) -> HLILError:
        """The error to raise about the node made at site (None: no line); the build keeps the first"""
        return self.kept(HLILError(self.locate(site, text)))

    def kept(self, error: HLILError) -> HLILError:
        """error, kept as the build's first unless one came before"""
        if self.first_error is None:
            self.first_error = error

        return error


_active: Build | None = None


def active_build() -> Build | None:
    return _active


@contextmanager
def activated(build: Build):
    """build is the active one inside the with block, the outer one again after it"""
    global _active
    outer, _active = _active, build
    try:
        yield
    finally:
        _active = outer


def dsl_error(text: str) -> HLILError:
    """An error about the DSL statement running: located and kept by the active build; outside one, at the statement
    the writer is compiling"""
    build = active_build()
    if build is not None:
        return build.fail(text)

    # Imported here: the writer imports this package's modules
    from ..scp_writer import get_scp_writer
    return HLILError(get_scp_writer().at_statement(text))
