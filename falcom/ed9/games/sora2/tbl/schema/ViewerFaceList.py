from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerFaceList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
        ('uint64_20', 'Q'),
        ('str28',     'S'),
    )
