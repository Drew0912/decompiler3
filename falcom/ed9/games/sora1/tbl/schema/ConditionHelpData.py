from falcom.ed9.parser.tbl import TableDataEntry


# t_itemhelp.tbl
class ConditionHelpData(TableDataEntry):
    DESCRIPTOR = (
        ('conditionId', 'W'),
        ('pad02',       'P6'),
        ('str08',       'S'),
        # the condition's name; formatted with a number for a help line whose SkillEffectHelpData format code is 17
        ('name',        'S'),
        ('str18',       'S'),
        ('str20',       'S'),
    )
