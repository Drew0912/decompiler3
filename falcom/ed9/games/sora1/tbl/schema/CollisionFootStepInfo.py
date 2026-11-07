from falcom.ed9.parser.tbl import TableDataEntry


# t_collision_info.tbl
class CollisionFootStepInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('arr32_08',  'A4'),
        ('uint32_14', 'I'),
        ('arr32_18',  'A4'),
        ('uint32_24', 'I'),
    )
