from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_roulette.tbl
class RouletteBetRate(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('uint64_20', 'Q'),
    )
