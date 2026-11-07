"""A kai1 script's first import: the shared helper's names, with Kai1ScpWriter as the writer"""

from falcom.ed9.writer.scp_writer import install_scp_writer as _install_scp_writer
from falcom.ed9.writer.scp_writer_helper import *
from .scp_writer import Kai1ScpWriter as _Kai1ScpWriter

_install_scp_writer(_Kai1ScpWriter())
