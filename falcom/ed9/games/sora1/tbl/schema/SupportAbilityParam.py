from falcom.ed9.parser.tbl import TableDataEntry


# t_support_ability.tbl
class SupportAbilityParam(TableDataEntry):
    DESCRIPTOR = (
        ('id',          'B'),
        ('linkId',      'B'),
        ('uint16_02',   'W'),
        ('uint32_04',   'I'),
        ('uint64_08',   'Q'),
        ('uint32_10',   'I'),
        ('uint32_14',   'I'),
        ('uint64_18',   'Q'),
        ('flags',       'S'),
        ('aniFunction', 'S'),
        ('name',        'S'),
        ('description', 'S'),
    )
