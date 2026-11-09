from falcom.ed9.parser.tbl import TableDataEntry


# t_npc_*.tbl
class NPCParam(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',         'W'),
        ('overrideChrId', 'W'),   # when model is empty, replaces the character's ID in setup; 0 or 0xFFFF: none
        ('uint32_04',     'I'),
        ('model',         'S'),
        ('flagsSet',      'A2'),  # scenario flags that must all be set
        ('uint32_1c',     'I'),
        ('flagsClear',    'A2'),  # scenario flags none of which may be set
        ('x',             'f'),   # x, y, z: a position, by its use
        ('y',             'f'),
        ('z',             'f'),
        ('angle',         'f'),   # degrees
        ('talkRadius',    'f'),   # 0 or less becomes 0.75
        ('float32_40',    'f'),
        ('lookPoint',     'W'),
        ('pad46',         'P2'),
        ('float32_48',    'f'),
        ('float32_4c',    'f'),
        ('float32_50',    'f'),
        ('uint32_54',     'I'),
        # flags, a bit per letter, landing in two masks; an unknown letter is logged:
        #   mask 1 (+0x58), copied into the character's flag word, usually with 0x8 and 0x8000 also set;
        #   scripts test that word with chr_check_flag(character, mask):
        #     H 0x2, G 0x8: scripts test them (H in script btlcom, G in function AniBtlDead); purpose not known
        #     A 0x4, C 0x10, P 0x100, L 0x200, T 0x400, S 0x1000, F 0x2000, U 0x4000, N 0x1000000: read by code,
        #       purpose not known (N only on the character's copy)
        #   mask 2 (+0x5C), not copied:
        #     X 0x4, V 0x8000: NPCs are placed by one of two paths, chosen by a condition whose meaning is not
        #       known: one places only V rows without X, the other skips every row with V or X
        #     D 0x200: sets 4 in another character field
        #     R 0x400: the script function named in talkFunction is looked up and apparently run, and the talk
        #       guide text says "report" in place of "talk"
        #     Y 0x2000: no trigger while a certain object (which: not known) is within 10.0
        #     K 0x2, W 0x8, E 0x10, Q 0x20, x 0x40, M 0x1000, d 0x4000: read by code, purpose not known
        #     4 0x800: nothing found reading it
        ('flags',         'S'),
        ('initFunction',  'S'),
        ('execFunction',  'S'),
        ('execArgument',  'i'),
        ('uint32_74',     'I'),
        ('talkFunction',  'S'),
        ('nearFunction',  'S'),
        ('uint32_88',     'I'),
        ('talkFlag',      'I'),
        ('shopIds',       'A2'),
        ('uint32_9c',     'I'),
    )


# t_npc_c0000.tbl
class NPCParam98(TableDataEntry):
    SECTION = 'NPCParam'
    DESCRIPTOR = (
        ('chrId',         'W'),
        ('overrideChrId', 'W'),
        ('uint32_04',     'I'),
        ('model',         'S'),
        ('flagsSet',      'A2'),
        ('uint32_1c',     'I'),
        ('flagsClear',    'A2'),
        ('x',             'f'),
        ('y',             'f'),
        ('z',             'f'),
        ('angle',         'f'),
        ('float32_3c',    'f'),
        ('uint32_40',     'I'),
        ('lookPoint',     'W'),
        ('pad46',         'P2'),
        ('uint32_48',     'I'),
        ('uint32_4c',     'I'),
        ('str50',         'S'),
        ('str58',         'S'),
        ('aniFunction',   'S'),
        ('uint64_68',     'Q'),
        ('str70',         'S'),
        ('str78',         'S'),
        ('uint64_80',     'Q'),
        ('arr16_88',      'A2'),
        ('uint32_94',     'I'),
    )
