"""IL Options - Generic options for all IL levels"""


class ILOptions:
    """Formatter flags on one IL instruction"""

    __slots__ = ('hidden_for_formatter',)

    hidden_for_formatter: bool

    def __init__(self):
        self.hidden_for_formatter = False
