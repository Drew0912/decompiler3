from falcom.ed9.parser.tbl import TableDataEntry


# t_ani_param.tbl
class AniParam(TableDataEntry):
    DESCRIPTOR = (
        ('str00',      'S'),
        ('uint32_08',  'I'),
        ('float32_0c', 'f'),
        ('float32_10', 'f'),
        ('float32_14', 'f'),
        ('float32_18', 'f'),
        ('float32_1c', 'f'),
        ('float32_20', 'f'),
        ('uint32_24',  'I'),
    )
