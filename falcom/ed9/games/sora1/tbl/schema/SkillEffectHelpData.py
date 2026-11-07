from falcom.ed9.parser.tbl import TableDataEntry


# t_itemhelp.tbl
class SkillEffectHelpData(TableDataEntry):
    DESCRIPTOR = (
        ('id',          'W'),
        ('pad02',       'P6'),
        ('text',        'S'),
        ('formatCodes', 'A4'),
        ('extraLines',  'I'),
        ('str20',       'S'),
        ('str28',       'S'),
        ('str30',       'S'),
        ('str38',       'S'),
        ('uint32_40',   'I'),
        ('uint32_44',   'I'),
        ('str48',       'S'),
        ('str50',       'S'),
    )
