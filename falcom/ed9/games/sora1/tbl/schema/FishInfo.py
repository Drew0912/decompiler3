from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_fishing.tbl
class FishInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('uint32_10',  'I'),
        ('uint32_14',  'I'),
        ('uint32_18',  'I'),
        ('uint32_1c',  'I'),
        ('uint32_20',  'I'),
        ('uint32_24',  'I'),
        ('uint32_28',  'I'),
        ('uint32_2c',  'I'),
        ('uint64_30',  'Q'),
        ('uint64_38',  'Q'),
        ('uint64_40',  'Q'),
        ('uint32_48',  'I'),
        ('uint32_4c',  'I'),
        ('uint64_50',  'Q'),
        ('uint64_58',  'Q'),
        ('uint64_60',  'Q'),
        ('uint32_68',  'I'),
        ('uint32_6c',  'I'),
        ('uint64_70',  'Q'),
        ('uint64_78',  'Q'),
        ('uint64_80',  'Q'),
        ('float32_88', 'f'),
        ('float32_8c', 'f'),
        ('float32_90', 'f'),
        ('float32_94', 'f'),
        ('float32_98', 'f'),
        ('uint32_9c',  'I'),
        ('stra0',      'S'),
    )
