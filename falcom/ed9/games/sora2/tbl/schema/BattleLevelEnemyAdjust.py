from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class BattleLevelEnemyAdjust(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
    )
