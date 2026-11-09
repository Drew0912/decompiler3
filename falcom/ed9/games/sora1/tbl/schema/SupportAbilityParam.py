from falcom.ed9.parser.tbl import TableDataEntry


# t_support_ability.tbl
class SupportAbilityParam(TableDataEntry):
    DESCRIPTOR = (
        ('id',          'B'),
        ('linkId',      'B'),  # another ability's ID; 0: none
        ('uint16_02',   'W'),
        ('uint32_04',   'I'),
        ('uint64_08',   'Q'),
        ('uint32_10',   'I'),
        ('uint32_14',   'I'),
        ('uint64_18',   'Q'),
        # flags, a bit per letter:
        #   1 0x1, C 0x2, S 0x4, N 0x8, P 0x10, A 0x20, Z 0x40: nothing found reading it
        ('flags',       'S'),
        ('aniFunction', 'S'),
        ('name',        'S'),
        ('description', 'S'),
    )
