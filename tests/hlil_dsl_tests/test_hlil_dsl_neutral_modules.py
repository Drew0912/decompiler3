#!/usr/bin/env python3
"""The HLIL DSL's VM-neutral modules (falcom/ed9/writer/hlil_dsl/__init__.py) import nothing from falcom.ed9 in an
import statement, at module level or inside a function (an importlib or __import__ call is not read), so they can
leave the ED9 package as they are when a second VM uses them"""

import ast
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

PACKAGE = 'falcom.ed9.writer.hlil_dsl'
PACKAGE_DIR = REPO_ROOT / 'falcom' / 'ed9' / 'writer' / 'hlil_dsl'
NEUTRAL_MODULES = ('nodes', 'calls', 'build', 'tree', 'source_check', 'stubs')
SHARED_PACKAGES = ('ir.core',)     # outside falcom.ed9: what every IR layer shares


def imported_modules(path: Path) -> list[str]:
    """Every module an import statement of path's source names, at any depth, a relative import made absolute"""
    package = PACKAGE.split('.')
    modules = []
    for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
        match node:
            case ast.Import():
                modules.extend(alias.name for alias in node.names)

            case ast.ImportFrom(level=0):
                modules.append(node.module)

            case ast.ImportFrom():
                base = package[:len(package) - node.level + 1]
                if node.module is None:
                    modules.extend('.'.join([*base, alias.name]) for alias in node.names)
                else:
                    modules.append('.'.join([*base, node.module]))

    return modules


class TestNeutralModules(unittest.TestCase):
    def test_they_import_nothing_from_falcom_ed9(self):
        neutral = {f'{PACKAGE}.{name}' for name in NEUTRAL_MODULES}
        for name in NEUTRAL_MODULES:
            for module in imported_modules(PACKAGE_DIR / f'{name}.py'):
                with self.subTest(module=name, imports=module):
                    allowed = (module in neutral or module.split('.')[0] in sys.stdlib_module_names
                               or any(module == shared or module.startswith(f'{shared}.')
                                      for shared in SHARED_PACKAGES))
                    self.assertTrue(allowed, f'{name}.py imports {module}')


if __name__ == '__main__':
    unittest.main()
