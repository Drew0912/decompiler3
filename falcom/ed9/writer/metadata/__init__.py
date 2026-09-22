"""Common-function library support: fingerprints, the generated index, and the generated modules"""

COMMON_LIBRARY_PACKAGE = 'falcom.ed9.writer.metadata.common'  # dotted path to the generated modules

# Every generated module and every emitted script needs this - one place both sides spell it
SCP_WRITER_HELPER_IMPORT = 'from falcom.ed9.writer.scp_writer_helper import *'

# Every emitted script imports the whole library unconditionally, not just the functions its own
# source matched - so a human editing the script has every common function in scope for
# autocomplete/CALL() even when adding one the original bytecode never used.
COMMON_LIBRARY_ALL_IMPORT = 'from falcom.ed9.writer.metadata.common_all import *'
