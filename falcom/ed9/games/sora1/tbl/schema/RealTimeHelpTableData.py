from falcom.ed9.parser.tbl import TableDataEntry


# t_help.tbl
class RealTimeHelpTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('uint32_04',  'I'),
        ('str08',      'S'),
        ('float32_10', 'f'),
        ('uint32_14',  'I'),
    )
