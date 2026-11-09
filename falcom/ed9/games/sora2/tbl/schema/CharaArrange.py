from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class CharaArrange(TableDataEntry):
    DESCRIPTOR = (
        ('uint16_00',   'W'),
        ('pad02',       'P2'),
        ('uint32_04',   'I'),
        ('aniFunction', 'S'),
        ('commands',    'S'),   # #-codes such as #E_0#M_0#B_0, read up to the first that does not parse
        ('str18',       'S'),
        ('x',           'f'),
        ('y',           'f'),
        ('z',           'f'),
        ('angle',       'f'),   # degrees, by its use
        # flags, a bit per letter:
        #   C 0x1, D 0x2, P 0x4: tested in that order; the first one set picks one of three ways to set the character
        #     up (what each does: not known); D reads float32_38 and float32_3c, P float32_38 to float32_40
        ('flags',       'S'),
        ('float32_38',  'f'),
        ('float32_3c',  'f'),
        ('float32_40',  'f'),
        ('pad44',       'P4'),
    )
