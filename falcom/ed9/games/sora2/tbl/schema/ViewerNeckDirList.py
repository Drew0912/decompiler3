from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerNeckDirList(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'I'),
        ('pad04',      'P4'),
        ('name',       'S'),
        ('float32_10', 'f'),
        ('float32_14', 'f'),
    )
