from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class TacticalBonus(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('amount',    'B'),
        ('progress',  'B'),
        ('maxCount',  'B'),
        ('pad07',     'P1'),
        ('name',      'S'),
    )
