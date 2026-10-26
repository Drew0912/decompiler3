"""One package per game on the ED9 VM, holding that game's data"""

from pathlib import Path

GAMES_PACKAGE = __name__
GAMES_DIR = Path(__file__).resolve().parent


def game_names() -> list[str]:
    """Every game here: each folder with its package"""
    return sorted(path.parent.name for path in GAMES_DIR.glob('*/__init__.py'))
