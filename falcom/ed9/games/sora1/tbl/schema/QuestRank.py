from falcom.ed9.parser.tbl import TableDataEntry


# t_quest.tbl, t_quest_fc.tbl
class QuestRank(TableDataEntry):
    DESCRIPTOR = (
        ('rank',      'I'),
        ('pad04',     'P4'),
        ('name',      'S'),
        ('threshold', 'I'),
        ('uint32_14', 'I'),
    )
