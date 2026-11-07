from falcom.ed9.parser.tbl import TableDataEntry


# t_costume.tbl
class CostumeAttachOffset(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',     'W'),
        ('pad02',     'P6'),
        ('name',      'S'),
        ('x',         'f'),
        ('y',         'f'),
        ('z',         'f'),
        ('rotationX', 'f'),
        ('rotationY', 'f'),
        ('rotationZ', 'f'),
        ('scaleX',    'f'),
        ('scaleY',    'f'),
        ('scaleZ',    'f'),
        ('uint32_34', 'I'),
    )
