"""The lowering's sink at compile time (docs/dsl/HLIL_DSL.md, Recompile Path): each opcode through its DSL opcode
function, so handle_opcode, the opcode callbacks, the call tracker and the compile check see it as an LLIL body's, at
the line of the HLIL node it came from"""

from typing import TYPE_CHECKING

from ...assembler import ED9Opcode
from .. import scp_writer_opcode_handler

if TYPE_CHECKING:
    from ..scp_writer import ScpWriter


class LLILSink:
    def __init__(self, writer: 'ScpWriter'):
        self.writer = writer

    def at(self, site):
        """Sets the writer's lowering_site, which the writer clears after the lowering"""
        self.writer.lowering_site = site

    def new_label(self) -> str:
        """Named for the function compiling and counted in it, so a body lowered into two functions, or twice into one,
        gets fresh names"""
        f = self.writer.current_function
        name = f'{f.name}:{f.lowered_labels}'
        f.lowered_labels += 1
        return name

    def label(self, name: str):
        self.writer.add_label(name)

    def emit(self, opcode: ED9Opcode, *operands):
        opcode_function = getattr(scp_writer_opcode_handler, opcode.name)
        opcode_function(*operands)
