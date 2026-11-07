from falcom.ed9.parser.tbl import TableDataEntry


# t_chrdata.tbl
class PortraitDataParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('float32_18', 'f'),
        ('float32_1c', 'f'),
        ('float32_20', 'f'),
        ('float32_24', 'f'),
        ('float32_28', 'f'),
        ('float32_2c', 'f'),
    )
