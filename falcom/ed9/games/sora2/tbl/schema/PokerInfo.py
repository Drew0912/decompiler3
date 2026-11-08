from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_poker.tbl
class PokerInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint16_00',    'W'),
        ('defaultValue', 'W'),
        ('flag1',        'W'),  # 0: none
        ('value1',       'W'),
        ('flag2',        'W'),
        ('value2',       'W'),
    )
