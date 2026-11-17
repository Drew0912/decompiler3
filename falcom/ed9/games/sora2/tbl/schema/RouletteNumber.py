from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_roulette.tbl
class RouletteNumber(TableDataEntry):
    DESCRIPTOR = (
        ('key',        'I'),
        # degrees: the number's slot on the wheel (a reading), 360/38 wide; the code uses its centre
        ('angleStart', 'f'),
        ('angleEnd',   'f'),
    )
