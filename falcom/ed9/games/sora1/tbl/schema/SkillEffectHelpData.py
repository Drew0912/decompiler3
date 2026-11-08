from falcom.ed9.parser.tbl import TableDataEntry


# t_itemhelp.tbl
class SkillEffectHelpData(TableDataEntry):
    DESCRIPTOR = (
        ('id',             'W'),   # the effect ID
        ('pad02',          'P6'),
        ('text',           'S'),
        ('formatCodes',    'A4'),  # one per line: 1 = plain %d, 4 = %s, 16 = %s and (%d turns); empty: text as it is
        ('extraLines',     'i'),   # lines after the first; -1: no lines; the second takes secondPassIcon for icon
        ('firstPassText',  'S'),
        ('laterPassText',  'S'),
        ('prefix',         'S'),   # put before the text, after any icon
        ('str38',          'S'),
        ('icon',           'I'),
        ('secondPassIcon', 'I'),
        ('str48',          'S'),
        ('str50',          'S'),
    )
