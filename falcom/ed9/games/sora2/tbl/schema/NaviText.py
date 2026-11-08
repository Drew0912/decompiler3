from falcom.ed9.parser.tbl import TableDataEntry


# t_quest.tbl
class NaviText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('text',       'S'),
        ('altText',    'S'),
        ('flagsSet',   'A2'),  # scenario flags that must all be set
        ('uint32_24',  'I'),
        ('flagsClear', 'A2'),  # scenario flags none of which may be set
        ('uint32_34',  'I'),
    )
