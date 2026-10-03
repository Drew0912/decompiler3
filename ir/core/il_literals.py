'''IL constant values: how they print, when two are the same constant, and which is a plain zero'''


class SourceFloat(float):
    '''A float that prints as the spelling its source used (e.g. 0.3 for the stored 0.2999999523162842).

    The value stays exact - repr() and arithmetic see the real float, and arithmetic returns a plain float
    without text. The lifter that decodes the value supplies the text.
    '''
    __slots__ = ('text',)

    def __new__(cls, value: float, text: str | None = None):
        self = super().__new__(cls, value)
        self.text = text
        return self

    def __str__(self) -> str:
        return self.text if self.text is not None else float.__repr__(self)


def constant_values_equal(a, b) -> bool:
    '''Whether two IL constant values are the same constant: same type (int, float and SourceFloat never
    merge) and, for floats, the same bits and the same printed text (-0.0 is not 0.0; NaN, which binary
    data can decode to, equals itself).'''
    if type(a) != type(b):
        return False

    if isinstance(a, float):
        # hex() keeps the sign of zero and spells every NaN 'nan'; str() is a SourceFloat's text
        return a.hex() == b.hex() and str(a) == str(b)

    return a == b


def is_int_zero(value) -> bool:
    '''A zero int constant (False included: bool is an int): a comparison with it is a plain truth test. A
    float zero is not one - a float's truth in the VM is unverified.'''
    return isinstance(value, int) and value == 0
