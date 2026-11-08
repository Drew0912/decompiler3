from falcom.ed9.parser.tbl import TableDataEntry


# t_costume.tbl
class CostumeAttachOffset(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',     'W'),   # a character's ID, by its use
        ('pad02',     'P6'),
        ('name',      'S'),
        ('x',         'f'),
        ('y',         'f'),
        ('z',         'f'),
        ('rotationX', 'f'),   # degrees, by its use
        ('rotationY', 'f'),
        ('rotationZ', 'f'),
        ('scaleX',    'f'),
        ('scaleY',    'f'),
        ('scaleZ',    'f'),
        ('uint32_34', 'I'),
    )
