"""Common-function library support: fingerprints, the generated index, and the generated modules"""

COMMON_LIBRARY_PACKAGE = 'falcom.ed9.writer.metadata.common'  # dotted path to the generated modules

# Every generated module and every emitted script needs this - one place both sides spell it
SCP_WRITER_HELPER_IMPORT = 'from falcom.ed9.writer.scp_writer_helper import *'
