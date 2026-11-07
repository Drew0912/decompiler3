from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerEyeLineList(TableDataEntry):
    DESCRIPTOR = (
        ('id',    'I'),
        ('pad04', 'P4'),
        ('name',  'S'),
        ('str10', 'S'),
    )
