from falcom.ed9.parser.tbl import TableDataEntry


# t_mapjump.tbl
class MapJumpSpotData(TableDataEntry):
    DESCRIPTOR = (
        ('id',           'I'),
        ('uint32_04',    'I'),
        ('areaId',       'I'),
        ('pad0c',        'P4'),
        ('name',         'S'),
        ('uint32_18',    'I'),
        ('pad1c',        'P4'),
        ('mapKey',       'S'),   # picks among rows with the same ID
        ('x',            'f'),
        ('y',            'f'),
        ('z',            'f'),
        ('uint32_34',    'I'),
        ('targetMapKey', 'S'),
        ('markerKey',    'I'),
        ('targetX',      'f'),
        ('targetY',      'f'),
        ('targetZ',      'f'),
        ('targetAngle',  'f'),   # degrees, by its use
        ('uint32_54',    'I'),
        ('flags',        'S'),
        ('variant',      'B'),
        ('pad61',        'P7'),
        ('defaultText',  'S'),   # used when flagsSet and flagsClear are empty or fail
        ('flagsSet',     'A2'),  # scenario flags that must all be set
        ('uint32_7c',    'I'),
        ('flagsClear',   'A2'),  # scenario flags none of which may be set
        ('uint32_8c',    'I'),
        ('altText',      'S'),
    )
