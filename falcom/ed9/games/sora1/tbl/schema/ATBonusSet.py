from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class ATBonusSet(TableDataEntry):
    DESCRIPTOR = (
        ('key',      'I'),
        ('side',     'B'),
        ('uint8_05', 'B'),
        ('uint8_06', 'B'),
        ('uint8_07', 'B'),
        ('uint8_08', 'B'),
        ('uint8_09', 'B'),
        ('uint8_0a', 'B'),
        ('uint8_0b', 'B'),
        ('uint8_0c', 'B'),
        ('uint8_0d', 'B'),
        ('uint8_0e', 'B'),
        ('uint8_0f', 'B'),
        ('uint8_10', 'B'),
        ('uint8_11', 'B'),
        ('uint8_12', 'B'),
        ('pad13',    'P1'),
    )
