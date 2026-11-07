from falcom.ed9.parser.tbl import TableDataEntry


# t_support_ability.tbl
class SupportLevelData(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',     'W'),
        ('level',     'B'),
        ('pad03',     'P1'),
        ('threshold', 'I'),
        ('abilityId', 'B'),
        ('pad09',     'P3'),
    )
