from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_roulette.tbl
class RouletteRuleText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )
