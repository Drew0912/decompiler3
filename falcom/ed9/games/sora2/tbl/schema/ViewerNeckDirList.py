from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerNeckDirList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('float32_10', 'f'),
        ('float32_14', 'f'),
    )
