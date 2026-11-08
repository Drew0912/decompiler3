from falcom.ed9.parser.tbl import TableDataEntry


# t_quest.tbl
class QuestText38(TableDataEntry):
    SECTION = 'QuestText'
    DESCRIPTOR = (
        ('questId',   'W'),
        ('stage',     'W'),
        ('pad04',     'P4'),
        ('text',      'S'),
        ('flagsSet',  'A2'),  # scenario flags that must all be set; a 0 rejects
        ('uint32_1c', 'I'),
        ('arr16_20',  'A2'),
        ('uint32_2c', 'I'),
        ('str30',     'S'),
    )
