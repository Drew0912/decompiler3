from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class BattleEnemyDamageAdjust(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
    )
