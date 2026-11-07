from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerCharaEquipList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )
