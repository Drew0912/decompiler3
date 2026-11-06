"""Decompile kai1's .dat scripts with falcom/ed9/scp2py_base.py's pipeline, into this folder's out/

Usage:
    python falcom/ed9/games/kai1/scp2py.py {file_path} [-o {output_dir}]

Flags live in falcom/ed9/scp2py_config.py, shared by every game.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from falcom.ed9.scp2py_base import main


if __name__ == '__main__':
    sys.exit(main('kai1'))
