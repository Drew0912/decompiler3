from falcom.ed9.parser.tbl import TableDataEntry


# t_skill.tbl
class SkillParam(TableDataEntry):
    DESCRIPTOR = (
        ('id',            'W'),
        ('chrId',         'W'),
        ('pad04',         'P4'),
        # flags, a bit per letter:
        #   (ItemTableData flags uses the same letters and bits)
        #   F 0x1000, E 0x2000, S 0x4000: may target a unit on the user's own side, on the other side, or the user
        #     (two units are on opposite sides when exactly one has type 3; what type 3 is: not known)
        #   T 0x100000: left out of some lists built from the skill table (which: not known)
        #   H 0x10000000: description alone is used as the help text
        #   R 0x8000, C 0x10000, I 0x20000, B 0x40000, A 0x200000, O 0x400000, G 0x800000, D 0x1000000,
        #     N 0x4000000, Q 0x20000000, X 0x40000000: read by code, purpose not known
        #   M 0x80000, P 0x2000000, L 0x8000000, b 0x80000000: nothing found reading them for skills
        ('flags',         'S'),
        ('kind',          'B'),
        ('uint8_11',      'B'),
        ('pad12',         'P6'),
        # flags2, a bit per letter:
        #   r 0x20: a skill without r fails an unknown check on a unit whose StatusParam flags have r
        #   K 0x40: a same-side target doesn't need F in flags; it must pass a different, unexplained test instead
        #   M 0x1, C 0x2, H 0x4, S 0x100, Z 0x200: read by code, purpose not known
        #   T 0x8, O 0x10, o 0x80: nothing found reading it
        ('flags2',        'S'),
        ('typeCode',      'W'),
        ('pad22',         'P2'),
        ('float32_24',    'f'),
        ('float32_28',    'f'),
        ('float32_2c',    'f'),
        ('effect1Id',     'W'),   # effectNArg1..3 depend on effectNId (N = 1 to 5)
        ('pad32',         'P2'),
        ('effect1Arg1',   'i'),
        ('effect1Arg2',   'i'),
        ('effect1Arg3',   'I'),
        ('effect2Id',     'W'),
        ('pad42',         'P2'),
        ('effect2Arg1',   'i'),
        ('effect2Arg2',   'i'),
        ('effect2Arg3',   'I'),
        ('effect3Id',     'W'),
        ('pad52',         'P2'),
        ('effect3Arg1',   'i'),
        ('effect3Arg2',   'i'),
        ('effect3Arg3',   'I'),
        ('effect4Id',     'W'),
        ('pad62',         'P2'),
        ('effect4Arg1',   'i'),
        ('effect4Arg2',   'i'),
        ('effect4Arg3',   'I'),
        ('effect5Id',     'W'),
        ('pad72',         'P2'),
        ('effect5Arg1',   'i'),
        ('effect5Arg2',   'i'),
        ('effect5Arg3',   'I'),
        ('float32_80',    'f'),
        ('chantTime',     'w'),
        ('stiffnessTime', 'w'),
        ('cost',          'w'),
        ('learnLevel',    'w'),
        ('sortKey',       'W'),
        ('uint16_8e',     'W'),
        ('aniFunction',   'S'),
        ('name',          'S'),
        ('stra0',         'S'),
        ('description',   'S'),
    )
