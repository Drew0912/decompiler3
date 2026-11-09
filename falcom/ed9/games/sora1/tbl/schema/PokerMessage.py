from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_poker.tbl
class PokerMessage(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('state',     'I'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )
