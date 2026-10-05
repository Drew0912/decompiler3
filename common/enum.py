from enum import IntEnum, IntFlag

__all__ = (
    'IntEnum2',
    'IntFlag2',
)

class IntEnum2(IntEnum):
    def __str__(self):
        return self.name

    def __repr__(self):
        return self.__str__()

class IntFlag2(IntFlag):
    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name
