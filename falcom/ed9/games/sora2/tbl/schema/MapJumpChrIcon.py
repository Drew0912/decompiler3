from falcom.ed9.parser.tbl import TableDataEntry


# t_mapjump.tbl
class MapJumpChrIcon(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',      'I'),
        ('float32_04', 'f'),
        ('uint32_08',  'I'),
    )
