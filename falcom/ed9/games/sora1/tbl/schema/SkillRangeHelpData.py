from falcom.ed9.parser.tbl import TableDataEntry


# t_itemhelp.tbl
class SkillRangeHelpData(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'W'),
        ('pad02',     'P6'),
        ('name',      'S'),
        ('uint32_10', 'I'),
        ('pad14',     'P4'),
        # item help: the second argument, after uint32_10, of the format text under the key TXT_ITEM_HELP_FORMAT1
        ('str18',     'S'),
        ('str20',     'S'),
    )
