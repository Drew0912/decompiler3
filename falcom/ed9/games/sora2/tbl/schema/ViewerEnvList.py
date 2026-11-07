from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerEnvList(TableDataEntry):
    DESCRIPTOR = (
        ('id',    'I'),
        ('pad04', 'P4'),
        ('name',  'S'),
    )
