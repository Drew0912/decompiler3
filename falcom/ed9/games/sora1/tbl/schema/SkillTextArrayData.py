from falcom.ed9.parser.tbl import TableDataEntry


# t_itemhelp.tbl
class SkillTextArrayData(TableDataEntry):
    DESCRIPTOR = (
        ('key1',  'W'),   # 0, 1 or 2 in every lookup found
        ('key2',  'W'),   # 0: the default row, used when no row has the key2 asked for
        ('pad04', 'P4'),
        ('str08', 'S'),
        ('str10', 'S'),
    )
