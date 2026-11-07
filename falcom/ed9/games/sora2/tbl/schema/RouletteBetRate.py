from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_roulette.tbl
class RouletteBetRate(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'I'),
        ('pad04',     'P4'),
        ('str08',     'S'),
        ('name',      'S'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('uint64_20', 'Q'),
    )
