from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_poker.tbl
class PokerHelp(TableDataEntry):
    DESCRIPTOR = (
        ('key',   'I'),
        ('pad04', 'P4'),
        ('text',  'S'),
    )
