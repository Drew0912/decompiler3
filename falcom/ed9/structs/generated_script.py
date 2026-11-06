"""The lines generated scripts and modules share"""

from dc3.utils import PROJECT_ROOT

# First lines of every generated script: the generating checkout's root, so it runs without PYTHONPATH
SYS_PATH_SETUP_LINES = ['import sys', f'sys.path.insert(0, {str(PROJECT_ROOT)!r})']

# PEP 8's two blank lines after each top-level definition of a generated script, and after its header
DEFINITION_SPACING = ['', '']

# Every generated module and every emitted script needs this - one place both sides spell it
SCP_WRITER_HELPER_IMPORT = 'from falcom.ed9.writer.scp_writer_helper import *'
