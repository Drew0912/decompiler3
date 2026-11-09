from falcom.ed9.parser.tbl import TableDataEntry


# t_item.tbl
class ItemTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',          'I'),   # rows sorted by it at load
        ('pad04',       'P4'),
        ('chrIds',      'A4'),  # a first 0xFFFF: any character
        ('uint32_14',   'I'),
        # flags, a bit per letter:
        #   (SkillParam flags uses the same letters and bits)
        #   B 0x40000, M 0x80000: at load, the item gets a skill row built for it, with its own skill ID (from 0x578)
        #   T 0x100000: left out of item lists, the shop's list among them
        #   H 0x10000000: description alone is used as the help text, except when category is 0x12
        #   F 0x1000, E 0x2000, S 0x4000, R 0x8000: read by code, purpose not known
        #   C 0x10000, I 0x20000, A 0x200000, O 0x400000, G 0x800000, D 0x1000000, P 0x2000000, N 0x4000000,
        #     L 0x8000000, Q 0x20000000, X 0x40000000, b 0x80000000: nothing found reading them for items
        ('flags',       'S'),
        # flags2, a bit per letter:
        #   M 0x4, F 0x8: equip check: an item with M needs a character whose StatusParam flags have M; an item with F
        #     and no M needs F
        #   H 0x40: while scenario flag 107 is set, one list of items (which: not known) drops the items without H
        #   other letters, including the digit 0, set no bit
        #   R 0x20: two places pick the colour (255, 236, 150) for the item in place of white
        #   L 0x2, 1 0x100000, 2 0x200000: read by code, purpose not known
        #   D 0x1, G 0x10: nothing found reading it
        ('flags2',      'S'),
        ('category',    'B'),
        ('subcategory', 'B'),
        ('uint16_2a',   'W'),
        ('uint16_2c',   'W'),
        ('uint8_2e',    'B'),
        ('pad2f',       'P1'),
        ('typeCode',    'W'),
        ('pad32',       'P2'),
        ('float32_34',  'f'),
        ('float32_38',  'f'),
        ('effect1Id',   'W'),   # effectNArg1..3 depend on effectNId (N = 1 to 5)
        ('pad3e',       'P2'),
        ('effect1Arg1', 'i'),
        ('effect1Arg2', 'i'),
        ('effect1Arg3', 'I'),
        ('effect2Id',   'W'),
        ('pad4e',       'P2'),
        ('effect2Arg1', 'i'),
        ('effect2Arg2', 'i'),
        ('effect2Arg3', 'I'),
        ('effect3Id',   'W'),
        ('pad5e',       'P2'),
        ('effect3Arg1', 'i'),
        ('effect3Arg2', 'i'),
        ('effect3Arg3', 'I'),
        ('effect4Id',   'W'),
        ('pad6e',       'P2'),
        ('effect4Arg1', 'i'),
        ('effect4Arg2', 'i'),
        ('effect4Arg3', 'I'),
        ('effect5Id',   'W'),
        ('pad7e',       'P2'),
        ('effect5Arg1', 'i'),
        ('effect5Arg2', 'i'),
        ('effect5Arg3', 'I'),
        ('float32_8c',  'f'),
        ('float32_90',  'f'),
        ('uint32_94',   'I'),
        ('uint32_98',   'I'),
        ('uint32_9c',   'I'),
        ('uint32_a0',   'I'),
        ('uint32_a4',   'I'),
        ('uint32_a8',   'I'),
        ('uint32_ac',   'I'),
        ('uint32_b0',   'I'),
        ('uint32_b4',   'I'),
        ('uint32_b8',   'I'),
        ('uint32_bc',   'I'),
        ('uint32_c0',   'I'),
        ('uint32_c4',   'I'),
        ('uint32_c8',   'I'),
        ('maxCount',    'I'),
        ('price',       'I'),
        ('padd4',       'P4'),
        ('useFunction', 'S'),
        ('name',        'S'),
        ('description', 'S'),
        ('uint32_f0',   'I'),
        ('uint32_f4',   'I'),
        ('icon',        'I'),   # icon % 4 = column, icon / 4 = row of a sheet, by its use
        ('uint32_fc',   'I'),
    )
