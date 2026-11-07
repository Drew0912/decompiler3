from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerWeaponList(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )
