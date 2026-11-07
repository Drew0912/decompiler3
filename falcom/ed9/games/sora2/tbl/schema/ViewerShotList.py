from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerShotList(TableDataEntry):
    DESCRIPTOR = (
        ('id',    'W'),
        ('pad02', 'P6'),
        ('name',  'S'),
    )
