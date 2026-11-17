from falcom.ed9.parser.tbl import TableDataEntry


# t_quest.tbl, t_quest_fc.tbl
class QuestRank(TableDataEntry):
    DESCRIPTOR = (
        ('rank',             'I'),
        ('pad04',            'P4'),
        ('name',             'S'),
        ('threshold',        'I'),
        ('itemId',           'W'),   # given on reaching the rank
        ('substituteItemId', 'W'),   # not 0: given instead when itemId is already held or equipped, by its use
    )
