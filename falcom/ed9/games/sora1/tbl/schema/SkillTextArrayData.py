from falcom.ed9.parser.tbl import TableDataEntry


# t_itemhelp.tbl
class SkillTextArrayData(TableDataEntry):
    DESCRIPTOR = (
        ('key1',  'W'),
        ('key2',  'W'),
        ('pad04', 'P4'),
        ('str08', 'S'),
        ('str10', 'S'),
    )
