"""Read sora1's .tbl tables with falcom/ed9/parser/tbl.py, into this folder's out/tbl/

Usage:
    python falcom/ed9/games/sora1/tbl2py.py {file_path} [-o {output_dir}]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from falcom.ed9.games.sora1.tbl import schema_all
from falcom.ed9.parser.tbl import main


if __name__ == '__main__':
    sys.exit(main('sora1', schema_all))
