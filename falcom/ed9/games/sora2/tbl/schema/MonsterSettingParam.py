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
        ('flagsSet',     'A2'),
        ('uint32_3c',    'I'),
        ('flagsClear',   'A2'),
        ('flag',         'W'),
        ('pad4e',        'P2'),
        ('battleArea',   'S'),
        ('uint8_58',     'B'),
        ('uint8_59',     'B'),
        ('uint8_5a',     'B'),
        ('uint8_5b',     'B'),
        ('x',            'f'),
        ('y',            'f'),
        ('z',            'f'),
        ('angle',        'f'),
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
