from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_fishing.tbl
class FishingRodInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('uint32_04',  'I'),
        ('uint32_08',  'I'),
        ('uint32_0c',  'I'),
        ('uint32_10',  'I'),
        ('uint32_14',  'I'),
        ('uint32_18',  'I'),
        ('uint32_1c',  'I'),
        ('uint32_20',  'I'),
        ('uint32_24',  'I'),
        ('uint32_28',  'I'),
        ('uint32_2c',  'I'),
        ('uint32_30',  'I'),
        ('uint32_34',  'I'),
        ('uint32_38',  'I'),
        ('uint32_3c',  'I'),
        ('uint32_40',  'I'),
        ('uint32_44',  'I'),
        ('uint32_48',  'I'),
        ('float32_4c', 'f'),
        ('float32_50', 'f'),
        ('float32_54', 'f'),
        ('float32_58', 'f'),
        ('float32_5c', 'f'),
    )
