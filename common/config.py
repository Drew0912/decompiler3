'''Global configuration system supporting JSON5 files and command-line overrides'''

import json5
import argparse
from pathlib import Path
from typing import Any


class Config:
    '''Global configuration singleton'''

    _instance = None
    _initialized = False

    # Default configuration values
    _defaults = {
        'endian': 'little',
        'encoding': 'UTF8',
    }

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self._config = self._defaults.copy()
            self._cli_overrides = {}
            self._initialized = True

    def load_file(self, filepath: str | Path) -> bool:
        '''Load configuration from JSON5 file'''
        filepath = Path(filepath)
        if not filepath.exists():
            return False

        try:
            with open(filepath, 'r', encoding = 'utf-8') as f:
                content = f.read()
                data = json5.loads(content)
                self._config.update(data)
                return True

        except Exception as e:
            print(f"Warning: Failed to load config from {filepath}: {e}")
            return False

    def load_defaults(self):
        '''Load default configuration files'''
        # Load project config
        project_config = Path(__file__).parent.parent / 'config.json5'
        self.load_file(project_config)

        # Load user config (overrides project config)
        # user_config = Path.home() / '.decompiler3' / 'config.json5'
        # self.load_file(user_config)

    def parse_args(self, args: list[str] = None):
        '''Parse command-line arguments and override config'''
        parser = argparse.ArgumentParser(
            description = 'decompiler3 configuration',
            add_help = False
        )

        parser.add_argument(
            '--config',
            type = str,
            help = 'Path to config file'
        )

        parser.add_argument(
            '--endian',
            type = str,
            choices = ['little', 'big'],
            help = 'Byte order (little/big)'
        )

        # Parse known args, ignore unknown
        parsed, _ = parser.parse_known_args(args)

        # Load config file if specified
        if parsed.config:
            self.load_file(parsed.config)

        # Apply command-line overrides
        if parsed.endian:
            self._cli_overrides['endian'] = parsed.endian

    def get(self, key: str, default: Any = None) -> Any:
        '''Get configuration value'''
        # CLI overrides have highest priority
        if key in self._cli_overrides:
            return self._cli_overrides[key]

        # Then config file values
        if key in self._config:
            return self._config[key]

        # Finally default value
        return default

    def set(self, key: str, value: Any):
        '''Set configuration value at runtime'''
        self._config[key] = value

    @property
    def endian(self) -> str:
        '''Get byte order configuration'''
        return self.get('endian')

    @property
    def encoding(self) -> str:
        '''Get encoding configuration'''
        return self.get('encoding')


# Global config instance
_config = Config()


def get_config() -> Config:
    '''Get global config instance'''
    return _config


def default_endian() -> str:
    '''Get default byte order (little/big)'''
    return _config.endian


def default_encoding() -> str:
    '''Get default encoding (UTF8/UTF16)'''
    return _config.encoding


def default_indent() -> str:
    '''Get default indent'''
    return '    '

def init_config(args: list[str] = None):
    '''Initialize configuration system'''
    _config.load_defaults()
    if args is not None:
        _config.parse_args(args)


# Auto-load defaults on import
_config.load_defaults()
