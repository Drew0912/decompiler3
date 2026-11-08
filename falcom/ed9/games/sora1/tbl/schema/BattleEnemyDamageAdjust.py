from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class BattleEnemyDamageAdjust(TableDataEntry):
    DESCRIPTOR = (
        ('threshold', 'i'),
        ('percent',   'i'),  # result * percent / 100 is added
    )
