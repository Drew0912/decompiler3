from falcom.ed9.parser.tbl import TableDataEntry


# t_skill.tbl
class SkillPowerIcon(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
    )
