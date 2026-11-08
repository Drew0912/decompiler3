from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class BattleEnemyLevelAdjust(TableDataEntry):
    DESCRIPTOR = (
        ('name',     'S'),
        ('flag',     'I'),  # scenario flag that must be set; 0: none
        ('levelAdd', 'I'),
    )
