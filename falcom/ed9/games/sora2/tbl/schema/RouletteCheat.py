from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_roulette.tbl
class RouletteCheat(TableDataEntry):
    DESCRIPTOR = (
        # the cheat value, kept in -100..100: it starts at a draw from rangeA to rangeB, and a draw from stepA
        # to stepB is added each time the cheat check runs; at 100 a cheatEnabled bet may set off the cheat
        ('rangeA',    'i'),
        ('rangeB',    'i'),
        ('stepA',     'i'),
        ('stepB',     'i'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),  # after a cheat hit, the value restarts at this (at 0 when the hit's kept number is -1)
    )
