from falcom.ed9.parser.tbl import TableDataEntry


# t_chrdata.tbl
class PortraitDataParam(TableDataEntry):
    DESCRIPTOR = (
        ('key',        'W'),
        ('pad02',      'P6'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('float32_18', 'f'),
        ('float32_1c', 'f'),
        ('float32_20', 'f'),
        ('float32_24', 'f'),
    )
