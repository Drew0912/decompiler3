"""A sora2 script's first import: the shared helper's names, with Sora2ScpWriter as the writer"""

from falcom.ed9.writer.scp_writer import install_scp_writer as _install_scp_writer
from falcom.ed9.writer.scp_writer_helper import *
from .scp_writer import Sora2ScpWriter as _Sora2ScpWriter

_install_scp_writer(_Sora2ScpWriter())
