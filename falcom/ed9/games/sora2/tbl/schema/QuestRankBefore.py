from falcom.ed9.parser.tbl import TableDataEntry


# t_quest.tbl
class QuestRankBefore(TableDataEntry):
    DESCRIPTOR = (
        ('rank',      'I'),
        ('threshold', 'I'),
        ('name',      'S'),
    )
