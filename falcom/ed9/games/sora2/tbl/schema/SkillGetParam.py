from falcom.ed9.parser.tbl import TableDataEntry


# t_skill.tbl
class SkillGetParam(TableDataEntry):
    DESCRIPTOR = (
        ('key',       'W'),
        ('uint16_02', 'W'),
        ('uint16_04', 'W'),
        ('uint16_06', 'W'),
        ('uint16_08', 'W'),
    )
