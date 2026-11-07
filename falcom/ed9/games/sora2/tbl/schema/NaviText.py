from falcom.ed9.parser.tbl import TableDataEntry


# t_quest.tbl
class NaviText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('text',       'S'),
        ('altText',    'S'),
        ('flagsSet',   'A2'),
        ('uint32_24',  'I'),
        ('flagsClear', 'A2'),
        ('uint32_34',  'I'),
    )
