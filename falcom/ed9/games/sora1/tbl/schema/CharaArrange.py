from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class CharaArrange(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('uint32_04',  'I'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('float32_18', 'f'),
        ('uint32_1c',  'I'),
        ('uint32_20',  'I'),
        ('float32_24', 'f'),
        ('str28',      'S'),
        ('uint32_30',  'I'),
        ('float32_34', 'f'),
        ('uint64_38',  'Q'),
    )
