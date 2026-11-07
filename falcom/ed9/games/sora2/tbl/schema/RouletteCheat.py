from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_roulette.tbl
class RouletteCheat(TableDataEntry):
    DESCRIPTOR = (
        ('rangeA',    'i'),
        ('rangeB',    'i'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
    )
