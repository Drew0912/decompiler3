from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class CharaArrange(TableDataEntry):
    DESCRIPTOR = (
        ('uint16_00',   'W'),
        ('pad02',       'P2'),
        ('uint32_04',   'I'),
        ('aniFunction', 'S'),
        ('str10',       'S'),
        ('float32_18',  'f'),
        ('uint32_1c',   'I'),
        ('uint32_20',   'I'),
        ('float32_24',  'f'),
        ('str28',       'S'),
        ('uint32_30',   'I'),
        ('float32_34',  'f'),
        ('uint64_38',   'Q'),
    )
