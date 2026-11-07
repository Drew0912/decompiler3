from falcom.ed9.parser.tbl import TableDataEntry


# t_quest.tbl, t_quest_fc.tbl
class QuestText(TableDataEntry):
    DESCRIPTOR = (
        ('questId',   'W'),
        ('uint16_02', 'W'),
        ('pad04',     'P4'),
        ('text',      'S'),
        ('flag',      'W'),
        ('pad12',     'P6'),
        ('str18',     'S'),
    )
