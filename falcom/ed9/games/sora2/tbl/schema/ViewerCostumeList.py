from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerCostumeList(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('str18',     'S'),
    )
