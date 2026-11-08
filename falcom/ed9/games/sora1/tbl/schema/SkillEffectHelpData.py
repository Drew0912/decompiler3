from falcom.ed9.parser.tbl import TableDataEntry


# t_itemhelp.tbl
class SkillEffectHelpData(TableDataEntry):
    DESCRIPTOR = (
        ('id',          'W'),   # the effect ID
        ('pad02',       'P6'),
        ('text',        'S'),
        ('formatCodes', 'A4'),  # one per line: 1 = plain %d, 4 = %s, 16 = %s and (%d turns); empty: text as it is
        ('extraLines',  'I'),   # lines after the first; the second uses uint32_44 in place of uint32_40
        ('str20',       'S'),
        ('str28',       'S'),
        ('str30',       'S'),
        ('str38',       'S'),
        ('uint32_40',   'I'),
        ('uint32_44',   'I'),
        ('str48',       'S'),
        ('str50',       'S'),
    )
