from falcom.ed9.parser.tbl import TableDataEntry


# t_quest.tbl, t_quest_fc.tbl
class QuestTitle(TableDataEntry):
    DESCRIPTOR = (
        ('id',            'W'),
        ('flags',         'B'),
        ('pad03',         'P5'),
        ('title',         'S'),
        ('client',        'S'),
        ('flags2',        'B'),   # bit 0: bp and mira shown only once the quest is complete (state bit 4)
        ('uint8_19',      'B'),
        ('uint8_1a',      'B'),
        ('pad1b',         'P5'),
        ('mapKey',        'S'),
        ('bp',            'B'),   # BP, by the node names; added to the total that QuestRank threshold is compared with
        ('pad29',         'P3'),
        ('mira',          'I'),   # a reward in mira, by the node names
        ('startFlag',     'W'),
        ('uint16_32',     'W'),
        ('listedFlag',    'W'),   # lists the quest once set; 0: none
        ('uint16_36',     'W'),
        ('uint16_38',     'W'),
        ('uint16_3a',     'W'),
        ('uint16_3c',     'W'),
        ('uint16_3e',     'W'),
        ('uint16_40',     'W'),
        ('pad42',         'P2'),
        ('importance',    'I'),   # 1 to 3: TXT_QUEST_IMPORTANT_1 to _3; else _NONE
        ('uint8_48',      'B'),
        ('pad49',         'P1'),
        ('category',      'W'),
        ('pad4c',         'P4'),
        ('str50',         'S'),
        ('reportComment', 'S'),   # shown once the quest is complete (state bit 4)
        ('linkedQuest',   'W'),   # another quest's ID, whose state bit 4 this one copies; 0: none
        ('pad62',         'P6'),
    )
