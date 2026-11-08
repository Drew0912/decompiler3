from falcom.ed9.parser.tbl import TableDataEntry


# t_help.tbl
class HelpPage(TableDataEntry):
    DESCRIPTOR = (
        ('titleId', 'W'),
        ('layout',  'B'),
        ('page',    'B'),
        ('pad04',   'P4'),
        ('texture', 'S'),
        ('text',    'S'),
        ('subText', 'S'),
    )
