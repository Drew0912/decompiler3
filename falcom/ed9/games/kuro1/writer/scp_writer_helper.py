"""A kuro1 script's first import: the shared helper's names, with Kuro1ScpWriter as the writer"""

from falcom.ed9.writer.scp_writer import install_scp_writer as _install_scp_writer
from falcom.ed9.writer.scp_writer_helper import *
from .scp_writer import Kuro1ScpWriter as _Kuro1ScpWriter

_install_scp_writer(_Kuro1ScpWriter())
