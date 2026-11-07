from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerCharaList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('str18',      'S'),
        ('uint32_20',  'I'),
        ('uint32_24',  'I'),
        ('str28',      'S'),
        ('str30',      'S'),
        ('float32_38', 'f'),
        ('float32_3c', 'f'),
    )
