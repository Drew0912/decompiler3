from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class BattleEnemyLevelStatusAdjust(TableDataEntry):
    DESCRIPTOR = (
        ('int16_00',  'w'),
        ('int16_02',  'w'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
    )
