from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class BattleEnemyLevelAdjust(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
    )
