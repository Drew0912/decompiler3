from falcom.ed9.parser.tbl import TableDataEntry


# t_npc_*.tbl
class NPCParam(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',         'W'),
        ('overrideChrId', 'W'),   # when model is empty, replaces the character's ID in setup; 0 or 0xFFFF: none
        ('uint32_04',     'I'),
        ('model',         'S'),
        ('flagsSet',      'A2'),  # scenario flags that must all be set
        ('uint32_1c',     'I'),
        ('flagsClear',    'A2'),  # scenario flags none of which may be set
        ('x',             'f'),   # x, y, z: a position, by its use
        ('y',             'f'),
        ('z',             'f'),
        ('angle',         'f'),   # degrees
        ('talkRadius',    'f'),   # 0 or less becomes 0.75
        ('float32_40',    'f'),
        ('lookPoint',     'W'),
        ('pad46',         'P2'),
        ('float32_48',    'f'),
        ('float32_4c',    'f'),
        ('float32_50',    'f'),
        ('uint32_54',     'I'),
        ('flags',         'S'),
        ('initFunction',  'S'),
        ('execFunction',  'S'),
        ('execArgument',  'i'),
        ('uint32_74',     'I'),
        ('talkFunction',  'S'),
        ('nearFunction',  'S'),
        ('uint32_88',     'I'),
        ('talkFlag',      'I'),
        ('shopIds',       'A2'),
        ('uint32_9c',     'I'),
    )


# t_npc_c0000.tbl
class NPCParam98(TableDataEntry):
    SECTION = 'NPCParam'
    DESCRIPTOR = (
        ('chrId',         'W'),
        ('overrideChrId', 'W'),
        ('uint32_04',     'I'),
        ('model',         'S'),
        ('flagsSet',      'A2'),
        ('uint32_1c',     'I'),
        ('flagsClear',    'A2'),
        ('x',             'f'),
        ('y',             'f'),
        ('z',             'f'),
        ('angle',         'f'),
        ('float32_3c',    'f'),
        ('uint32_40',     'I'),
        ('lookPoint',     'W'),
        ('pad46',         'P2'),
        ('uint32_48',     'I'),
        ('uint32_4c',     'I'),
        ('str50',         'S'),
        ('str58',         'S'),
        ('aniFunction',   'S'),
        ('uint64_68',     'Q'),
        ('str70',         'S'),
        ('str78',         'S'),
        ('uint64_80',     'Q'),
        ('arr16_88',      'A2'),
        ('uint32_94',     'I'),
    )
