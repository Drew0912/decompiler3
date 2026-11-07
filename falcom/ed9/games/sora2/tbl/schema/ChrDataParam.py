from falcom.ed9.parser.tbl import TableDataEntry


# t_chrdata.tbl
class ChrDataParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
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
        ('float32_30', 'f'),
        ('uint32_34',  'I'),
    )
