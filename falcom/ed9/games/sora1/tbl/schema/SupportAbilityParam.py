from falcom.ed9.parser.tbl import TableDataEntry


# t_support_ability.tbl
class SupportAbilityParam(TableDataEntry):
    DESCRIPTOR = (
        ('id',          'B'),
        ('linkId',      'B'),  # another ability's ID; 0: none
        ('uint8_02',    'B'),  # a reader skips a row whose byte differs from the value it is given
        ('uint8_03',    'B'),
        ('uint16_04',   'W'),
        ('pad06',       'P2'),
        ('uint64_08',   'Q'),
        ('uint32_10',   'I'),  # two readers skip a row below 100
        ('uint32_14',   'I'),
        ('uint64_18',   'Q'),
        # flags, a bit per letter:
        #   1 0x1: once a row has passed the other tests, it is skipped until the list of abilities is rebuilt
        #   P 0x10: while the character has condition 0x37 (Pommify), only rows with P pass
        #   Z 0x40: while scenario flag 104 is set, a row with Z passes only when one of a list of items has effect
        #     0x461, or one of four earlier checks lets it through (which items and checks: not known)
        #   C 0x2, S 0x4, N 0x8, A 0x20: read by code, purpose not known
        ('flags',       'S'),
        ('aniFunction', 'S'),  # the script function run for the ability; empty: none
        ('name',        'S'),
        ('description', 'S'),
    )
