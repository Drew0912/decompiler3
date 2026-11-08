from falcom.ed9.parser.tbl import TableDataEntry


# t_help.tbl
class RealTimeHelpTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'I'),
        ('flag',       'I'),  # 0: none; set when shown
        ('text',       'S'),
        ('float32_10', 'f'),
        ('uint32_14',  'I'),
    )
