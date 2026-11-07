from falcom.ed9.parser.tbl import TableDataEntry


# t_itemhelp.tbl
class SkillConnectListData(TableDataEntry):
    DESCRIPTOR = (
        ('uint16_00', 'W'),
        ('pad02',     'P6'),
        ('ids',       'A2'),
        ('uint32_14', 'I'),
    )
