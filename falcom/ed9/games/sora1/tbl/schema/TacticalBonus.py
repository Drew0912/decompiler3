from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class TacticalBonus(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
    )
