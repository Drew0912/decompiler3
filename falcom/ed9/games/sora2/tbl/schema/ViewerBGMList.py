from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerBGMList(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'I'),
        ('uint32_04', 'I'),
        ('name',      'S'),
        ('saveBit',   'I'),
        ('pad14',     'P4'),
    )
