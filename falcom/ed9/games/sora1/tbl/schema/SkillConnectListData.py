from falcom.ed9.parser.tbl import TableDataEntry


# t_itemhelp.tbl
class SkillConnectListData(TableDataEntry):
    DESCRIPTOR = (
        ('kind',      'W'),   # effects whose rows share a kind are joined into one help line
        ('pad02',     'P6'),
        ('ids',       'A2'),
        ('uint32_14', 'I'),
    )
