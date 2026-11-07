from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerHairList(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',   'W'),
        ('pad02',   'P2'),
        ('id',      'I'),
        ('name',    'S'),
        ('saveBit', 'I'),
        ('pad14',   'P4'),
    )
