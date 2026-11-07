from falcom.ed9.parser.tbl import TableDataEntry


# t_tips.tbl
class TipsTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'W'),
        ('uint16_02',  'W'),
        ('flag',       'W'),
        ('pad06',      'P2'),
        ('flagsClear', 'A2'),
        ('uint16_14',  'W'),
        ('pad16',      'P2'),
        ('flags',      'S'),
        ('uint8_20',   'B'),
        ('pad21',      'P3'),
        ('uint32_24',  'I'),
        ('title',      'S'),
        ('text',       'S'),
    )
