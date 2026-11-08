from falcom.ed9.parser.tbl import TableDataEntry


# t_mon_*.tbl
class MonsterSettingParam(TableDataEntry):
    DESCRIPTOR = (
        ('model',        'S'),
        ('chrId',        'W'),
        ('pad0a',        'P6'),
        ('arr32_10',     'A4'),
        ('uint32_1c',    'I'),
        ('flags',        'S'),
        ('uint16_28',    'W'),
        ('pad2a',        'P6'),
        ('flagsSet',     'A2'),  # scenario flags that must all be set
        ('uint32_3c',    'I'),
        ('flagsClear',   'A2'),  # scenario flags none of which may be set
        ('flag',         'W'),   # 0: none; set before str88 runs
        ('pad4e',        'P2'),
        ('battleArea',   'S'),
        ('countLow',     'B'),   # a random count: countLow + random % (countHigh - countLow + 1)
        ('countHigh',    'B'),   # high end of that count; below countLow, the count is countLow
        ('uint8_5a',     'B'),
        ('uint8_5b',     'B'),
        ('x',            'f'),   # x, y, z: a position, by its use
        ('y',            'f'),
        ('z',            'f'),
        ('angle',        'f'),   # degrees
        ('float32_6c',   'f'),
        ('int8_70',      'b'),
        ('int8_71',      'b'),
        ('pad72',        'P2'),
        ('uint32_74',    'I'),
        ('initFunction', 'S'),
        ('moveFunction', 'S'),
        ('str88',        'S'),
        ('arr32_90',     'A4'),
        ('uint32_9c',    'I'),
        ('bgmSet',       'I'),
        ('atBonus',      'I'),
        ('battleScript', 'S'),
    )


# t_mon_a1000.tbl, t_mon_a1005.tbl: no last string
class MonsterSettingParamA8(TableDataEntry):
    SECTION = 'MonsterSettingParam'
    DESCRIPTOR = MonsterSettingParam.DESCRIPTOR[:-1]
