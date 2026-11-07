from falcom.ed9.parser.tbl import TableDataEntry


# t_eventbox.tbl
class EventBoxTableData(TableDataEntry):
    DESCRIPTOR = (
        ('mapKey',     'S'),
        ('name',       'S'),
        ('function',   'S'),
        ('flagsSet',   'A2'),
        ('uint32_24',  'I'),
        ('flagsClear', 'A2'),
        ('uint32_34',  'I'),
    )
