from falcom.ed9.parser.tbl import TableDataEntry


# t_mon_*.tbl
class MonsterSettingParam(TableDataEntry):
    DESCRIPTOR = (
        ('model',        'S'),
        ('chrId',        'W'),
        ('pad0a',        'P6'),
        ('arr32_10',     'A4'),
        ('uint32_1c',    'I'),
        # flags, a bit per letter:
        #   D 0x1: sets bit 0x1 in the character's flag word, which scripts test with chr_check_flag (btlcom and
        #     btlitem do, at battle start and end and on item use)
        #   W 0x2: x, y, z give the position; angle, multiplied by a fixed game value, gives the angle
        #   L 0x4: only when W is not set: x, y, z and angle are run through a transform and added to another position
        #   A 0x8, E 0x10: read by code, purpose not known
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
