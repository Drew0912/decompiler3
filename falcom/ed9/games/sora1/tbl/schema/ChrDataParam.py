from falcom.ed9.parser.tbl import TableDataEntry


# t_chrdata.tbl
class ChrDataParam(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'W'),
        ('pad02',      'P2'),
        ('float32_04', 'f'),
        ('float32_08', 'f'),
        ('float32_0c', 'f'),
        ('float32_10', 'f'),
        ('float32_14', 'f'),
        ('float32_18', 'f'),
        ('float32_1c', 'f'),
        ('float32_20', 'f'),
        ('float32_24', 'f'),
        ('uint32_28',  'I'),
        ('uint32_2c',  'I'),
        ('str30',      'S'),
        ('float32_38', 'f'),
        ('uint32_3c',  'I'),
    )
