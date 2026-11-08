from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class BattleEnemyLevelStatusAdjust(TableDataEntry):
    DESCRIPTOR = (
        ('key',        'w'),  # -1: any
        ('levelBound', 'w'),
        ('uint32_04',  'I'),
        ('uint32_08',  'I'),
        ('uint32_0c',  'I'),
        ('uint32_10',  'I'),
    )
