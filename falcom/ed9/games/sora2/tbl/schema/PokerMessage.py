from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_poker.tbl
class PokerMessage(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',       'W'),
        ('pad02',       'P2'),
        ('state',       'I'),
        ('text',        'S'),
        ('uint64_10',   'Q'),
        ('aniFunction', 'S'),
    )
