from falcom.ed9.parser.tbl import TableDataEntry


# t_skill.tbl
class SkillGetParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint16_08', 'W'),
    )
