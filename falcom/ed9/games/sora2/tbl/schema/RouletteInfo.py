from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_roulette.tbl
class RouletteInfo(TableDataEntry):
    DESCRIPTOR = (
        ('objectId',  'W'),
        ('pad02',     'P2'),
        ('flag',      'I'),   # the first row whose flag is 0 or set is used
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
    )
