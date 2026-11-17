from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_roulette.tbl
class RouletteInfo(TableDataEntry):
    DESCRIPTOR = (
        ('objectId',      'W'),
        ('pad02',         'P2'),
        ('flag',          'I'),   # the first row whose flag is 0 or set is used
        ('chipValue',     'I'),   # medals per chip: times the chips placed is the bet
        ('spotChipLimit', 'I'),   # chips one spot takes; RouletteRuleText's first page shows it
        ('maxSpots',      'I'),   # how many spots chips may go on; so up to maxSpots * spotChipLimit chips in all
    )
