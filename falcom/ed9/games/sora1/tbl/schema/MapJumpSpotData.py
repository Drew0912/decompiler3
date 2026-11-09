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
        # flags, a bit per letter:
        #   A 0x1: without A, scenario flag 6000 + this row's id is set while the current place's id equals uint32_18
        #   N 0x2, F 0x4, E 0x8, T 0x10, L 0x20, P 0x40, R 0x80: read by code, purpose not known
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
