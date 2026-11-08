from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_roulette.tbl
class RouletteNumber(TableDataEntry):
    DESCRIPTOR = (
        ('key',        'I'),
        ('float32_04', 'f'),
        ('float32_08', 'f'),
    )
