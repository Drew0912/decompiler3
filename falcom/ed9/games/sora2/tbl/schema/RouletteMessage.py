from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_roulette.tbl
class RouletteMessage(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )
