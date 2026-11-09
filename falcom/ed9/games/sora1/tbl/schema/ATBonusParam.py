from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class ATBonusParam(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'B'),
        ('linkId',     'B'),   # another bonus's ID
        ('pad02',      'P6'),
        # flags, a bit per letter:
        #   A 0x1, S 0x4: read by code, purpose not known
        ('flags',      'S'),
        ('effectKind', 'B'),
        ('pad11',      'P3'),
        ('int32_14',   'i'),
        ('int32_18',   'i'),
        ('int32_1c',   'i'),
        ('name',       'S'),
    )
