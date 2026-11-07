from falcom.ed9.parser.tbl import TableDataEntry


# t_collision_info.tbl
class CollisionFootStepInfo(TableDataEntry):
    DESCRIPTOR = (
        ('key',       'I'),
        ('subKey',    'I'),
        ('soundIds',  'A4'),
        ('uint32_14', 'I'),
        ('soundIds2', 'A4'),
        ('uint32_24', 'I'),
    )
