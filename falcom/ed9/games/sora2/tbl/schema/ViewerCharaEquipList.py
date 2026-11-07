from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerCharaEquipList(TableDataEntry):
    DESCRIPTOR = (
        ('id',       'W'),
        ('pad02',    'P6'),
        ('name',     'S'),
        ('uint8_10', 'B'),
        ('pad11',    'P7'),
    )
