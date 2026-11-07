from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_card_battler.tbl
class LogText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )
