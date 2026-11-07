from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class BattleSCraftDamageRatio(TableDataEntry):
    DESCRIPTOR = (
        ('threshold', 'w'),
        ('ratio',     'w'),
    )
