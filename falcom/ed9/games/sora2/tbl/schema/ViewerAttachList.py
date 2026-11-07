from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerAttachList(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',     'W'),
        ('pad02',     'P2'),
        ('id',        'I'),
        ('name',      'S'),
        ('saveBit',   'I'),
        ('int8_14',   'b'),
        ('pad15',     'P3'),
        ('uint32_18', 'I'),
        ('pad1c',     'P4'),
    )
