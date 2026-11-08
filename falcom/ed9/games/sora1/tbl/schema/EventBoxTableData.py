from falcom.ed9.parser.tbl import TableDataEntry


# t_eventbox.tbl
class EventBoxTableData(TableDataEntry):
    DESCRIPTOR = (
        ('mapKey',     'S'),
        ('name',       'S'),
        ('function',   'S'),
        ('flagsSet',   'A2'),  # scenario flags that must all be set
        ('uint32_24',  'I'),
        ('flagsClear', 'A2'),  # scenario flags none of which may be set
        ('uint32_34',  'I'),
    )
