from falcom.ed9.parser.tbl import TableDataEntry


# t_help.tbl
class HelpTitle(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'W'),
        ('flag',      'W'),   # 0: always listed; else listed once set
        ('uint32_04', 'I'),
        ('title',     'S'),
        ('uint8_10',  'B'),
        ('pad11',     'P7'),
    )
