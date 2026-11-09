from falcom.ed9.parser.tbl import TableDataEntry


# t_costume.tbl
class CostumeParam(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',      'W'),   # 0xFFFF: any, in the lookups for kind 1 and 2
        ('kind',       'B'),
        ('pad03',      'P1'),
        ('variant',    'W'),
        ('flag',       'W'),   # 0: none
        # flags, a bit per letter:
        #   F 0x4: when costumes are looked up, a row with F is returned as soon as its scenario flag passes
        #   M 0x1, B 0x2, N 0x8, 2 0x10: read by code, purpose not known
        ('flags',      'S'),
        ('name',       'S'),
        ('partId',     'I'),
        ('pad1c',      'P4'),
        ('attachNode', 'S'),
        ('locator',    'S'),
        ('str30',      'S'),
    )
