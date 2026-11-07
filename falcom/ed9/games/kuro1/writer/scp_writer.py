"""What kuro1's scripts need of the writer: the older compiler's records (docs/falcom/ed9/ED9_FORMAT.md, Call-Site Debug
Records)"""

from falcom.ed9.structs.string_pool import StringPoolSection
from falcom.ed9.writer.scp_writer import PooledString, ScpFunction, ScpWriter


class Kuro1ScpWriter(ScpWriter):
    """Records on common functions too, each record String a pool entry of its own; kuro2 and kai1 inherit both"""

    @classmethod
    def _gets_debug_records(cls, f: ScpFunction) -> bool:
        return True

    def _debug_string(self, string: PooledString | None) -> PooledString | None:
        if string is None:
            return None

        return self._add_string(string.text, StringPoolSection.Debug)
