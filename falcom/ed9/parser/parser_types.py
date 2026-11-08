from dataclasses import dataclass


@dataclass(eq=False, repr=False)
class GlobalVar:
    index       : int
    name        : str
    type        : int

    def __str__(self) -> str:
        return f'global(index = {self.index}, name = {self.name!r}, type = {self.type})'

    __repr__ = __str__
