from falcom.ed9.parser.tbl import TableDataEntry


# t_orbment.tbl
class ArtsParam(TableDataEntry):
    DESCRIPTOR = (
        ('id',       'I'),
        ('uint8_04', 'B'),
        ('uint8_05', 'B'),
        ('uint8_06', 'B'),
        ('uint8_07', 'B'),
        ('uint8_08', 'B'),
        ('uint8_09', 'B'),
        ('uint8_0a', 'B'),
        ('pad0b',    'P1'),
        ('flag',     'I'),   # 0: none
    )
