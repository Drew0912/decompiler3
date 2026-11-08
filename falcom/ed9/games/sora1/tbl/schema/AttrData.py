from falcom.ed9.parser.tbl import TableDataEntry


# t_orbment.tbl
class AttrData(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'B'),
        ('pad01',     'P3'),
        ('cellIndex', 'I'),
        ('uint8_08',  'B'),
        ('uint8_09',  'B'),
        ('uint8_0a',  'B'),
        ('uint8_0b',  'B'),
        ('uint8_0c',  'B'),
        ('uint8_0d',  'B'),
        ('pad0e',     'P2'),
        ('str10',     'S'),
    )
