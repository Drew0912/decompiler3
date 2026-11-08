from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerWeaponList(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',   'W'),   # 0xFFFF: any
        ('pad02',   'P2'),
        ('id',      'I'),
        ('name',    'S'),
        ('saveBit', 'I'),
        ('pad14',   'P4'),
    )
