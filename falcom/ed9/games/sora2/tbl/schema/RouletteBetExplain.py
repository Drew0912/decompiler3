from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_roulette.tbl
class RouletteBetExplain(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )
