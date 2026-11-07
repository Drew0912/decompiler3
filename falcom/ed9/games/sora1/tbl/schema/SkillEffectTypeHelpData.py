from falcom.ed9.parser.tbl import TableDataEntry


# t_itemhelp.tbl
class SkillEffectTypeHelpData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )
