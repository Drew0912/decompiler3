from falcom.ed9.parser.tbl import TableDataEntry


# t_quest.tbl, t_quest_fc.tbl
class QuestTitle(TableDataEntry):
    DESCRIPTOR = (
        ('id',            'W'),
        ('flags',         'B'),
        ('pad03',         'P5'),
        ('title',         'S'),
        ('client',        'S'),
        ('flags2',        'B'),
        ('uint8_19',      'B'),
        ('uint8_1a',      'B'),
        ('pad1b',         'P5'),
        ('mapKey',        'S'),
        ('points',        'B'),
        ('pad29',         'P3'),
        ('uint32_2c',     'I'),
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
        ('importance',    'I'),
        ('uint8_48',      'B'),
        ('pad49',         'P1'),
        ('category',      'W'),
        ('pad4c',         'P4'),
        ('str50',         'S'),
        ('reportComment', 'S'),
        ('linkedQuest',   'W'),   # another quest's ID, whose state bit 4 this one copies; 0: none
        ('pad62',         'P6'),
    )
