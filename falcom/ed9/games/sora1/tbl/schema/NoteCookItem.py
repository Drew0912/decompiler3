from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteCookItem(TableDataEntry):
    DESCRIPTOR = (
        ('category',      'B'),
        ('pad01',         'P3'),
        ('itemId',        'I'),
        ('failItemId',    'I'),
        ('uint32_0c',     'I'),
        ('str10',         'S'),
        ('selector',      'W'),
        ('pad1a',         'P2'),
        ('selectorValue', 'I'),
        ('text',          'S'),
        ('chrRolls',      'A1'),
        ('uint32_34',     'I'),
    )
