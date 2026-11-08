from falcom.ed9.parser.tbl import TableDataEntry


# t_marker.tbl
class MarkerTableData(TableDataEntry):
    DESCRIPTOR = (
        ('eventKind',  'W'),   # compared with 0x1AA to 0x1AC, like clipKind
        ('clipKind',   'W'),   # 0x1AA ev_main, 0x1AB ev_quest, 0x1AC ev_sub; the smallest wins
        ('pad04',      'P4'),
        ('keys',       'A4'),
        ('uint32_14',  'I'),
        ('flagsSet',   'A2'),  # scenario flags that must all be set
        ('uint32_24',  'I'),
        ('flagsClear', 'A2'),  # scenario flags none of which may be set
        ('kind',       'B'),
        ('pad35',      'P1'),
        ('chrId',      'W'),
        ('uint32_38',  'I'),
        ('pad3c',      'P4'),
        ('str40',      'S'),
        ('areaId',     'W'),
        ('spotId',     'W'),
        ('float32_4c', 'f'),
        ('float32_50', 'f'),
        ('float32_54', 'f'),
        ('float32_58', 'f'),
        ('float32_5c', 'f'),
        ('float32_60', 'f'),
        ('uint32_64',  'I'),
        ('str68',      'S'),
    )
