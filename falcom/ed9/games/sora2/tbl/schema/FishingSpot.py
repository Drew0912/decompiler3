from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_fishing.tbl
class FishingSpot(TableDataEntry):
    DESCRIPTOR = (
        ('mapKey',      'S'),
        ('name',        'S'),
        ('smallCount',  'w'),   # 0 or less becomes 1
        ('middleCount', 'w'),   # 0 or less becomes 1
        ('largeCount',  'w'),   # 0 or less becomes 1
        ('pad16',       'P2'),
        ('flagsSet',    'A2'),  # scenario flags that must all be set
        ('uint32_24',   'I'),
        ('flagsClear',  'A2'),  # scenario flags none of which may be set
        ('fish1',       'I'),
        ('uint32_38',   'I'),
        ('uint32_3c',   'I'),
        ('uint32_40',   'I'),
        ('fish2',       'I'),
        ('uint32_48',   'I'),
        ('uint32_4c',   'I'),
        ('uint32_50',   'I'),
        ('fish3',       'I'),
        ('uint32_58',   'I'),
        ('uint32_5c',   'I'),
        ('uint32_60',   'I'),
        ('fish4',       'I'),
        ('uint32_68',   'I'),
        ('uint32_6c',   'I'),
        ('uint32_70',   'I'),
        ('fish5',       'I'),
        ('uint32_78',   'I'),
        ('uint32_7c',   'I'),
        ('uint32_80',   'I'),
        ('fish6',       'I'),
        ('uint32_88',   'I'),
        ('uint32_8c',   'I'),
        ('uint32_90',   'I'),
        ('fish7',       'I'),
        ('uint32_98',   'I'),
        ('uint32_9c',   'I'),
        ('uint32_a0',   'I'),
        ('fish8',       'I'),
        ('uint32_a8',   'I'),
        ('uint32_ac',   'I'),
        ('uint32_b0',   'I'),
        ('uint32_b4',   'I'),
    )
