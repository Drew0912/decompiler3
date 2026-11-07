from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerEnvList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )
