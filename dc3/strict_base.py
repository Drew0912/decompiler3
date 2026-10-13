'''Strict base class that prevents dynamic attribute assignment'''

import annotationlib

__all__ = (
    'StrictBase',
)


class StrictBase:
    '''Base class that only allows annotated attributes. For classes nothing subclasses: a subclass may set only the
    attributes it annotates itself'''
    _allowed_attrs_: frozenset[str]

    def __init_subclass__(cls):
        # Names only, unevaluated: an annotation may name a TYPE_CHECKING-only import
        cls._allowed_attrs_ = frozenset(annotationlib.get_annotations(cls, format = annotationlib.Format.STRING))

    def __setattr__(self, name, value):
        if name not in self._allowed_attrs_:
            raise AttributeError(f"Unknown attribute {name!r}")

        return object.__setattr__(self, name, value)
