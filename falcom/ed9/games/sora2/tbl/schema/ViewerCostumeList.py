from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerCostumeList(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',     'W'),
        ('pad02',     'P2'),
        ('id',        'I'),
        ('name',      'S'),
        ('saveBit',   'I'),
        ('uint32_14', 'I'),
        ('flags',     'S'),
    )
