from falcom.ed9.parser.tbl import TableDataEntry


# t_help.tbl
class RealTimeHelpTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'I'),
        ('flag',      'I'),  # 0: none; set when shown
        ('text',      'S'),
        ('duration',  'f'),  # seconds (a reading) until the popup closes; 0 or less (-1): it stays until closed
        ('uint32_14', 'I'),
    )
