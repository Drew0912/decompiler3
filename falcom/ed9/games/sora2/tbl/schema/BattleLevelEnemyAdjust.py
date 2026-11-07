from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class BattleLevelEnemyAdjust(TableDataEntry):
    DESCRIPTOR = (
        ('name',      'S'),
        ('key',       'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
    )
