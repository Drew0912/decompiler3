"""A kuro2 script's first import: the shared helper's names, with Kuro2ScpWriter as the writer"""

from falcom.ed9.writer.scp_writer import install_scp_writer as _install_scp_writer
from falcom.ed9.writer.scp_writer_helper import *
from .scp_writer import Kuro2ScpWriter as _Kuro2ScpWriter

_install_scp_writer(_Kuro2ScpWriter())
