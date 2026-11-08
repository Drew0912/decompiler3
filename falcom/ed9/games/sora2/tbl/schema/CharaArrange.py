from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class CharaArrange(TableDataEntry):
    DESCRIPTOR = (
        ('uint16_00',   'W'),
        ('pad02',       'P2'),
        ('uint32_04',   'I'),
        ('aniFunction', 'S'),
        ('str10',       'S'),
        ('str18',       'S'),
        ('x',           'f'),
        ('y',           'f'),
        ('z',           'f'),
        ('angle',       'f'),   # degrees, by its use
        ('flags',       'S'),
        ('float32_38',  'f'),
        ('float32_3c',  'f'),
        ('float32_40',  'f'),
        ('pad44',       'P4'),
    )
