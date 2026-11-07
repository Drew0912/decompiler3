from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class BattleEnemyLevelAdjust(TableDataEntry):
    DESCRIPTOR = (
        ('name',     'S'),
        ('flag',     'I'),
        ('levelAdd', 'I'),
    )
