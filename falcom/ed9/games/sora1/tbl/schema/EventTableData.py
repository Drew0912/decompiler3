from falcom.ed9.parser.tbl import TableDataEntry


# t_evtable.tbl
class EventTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',            'W'),
        ('pad02',         'P6'),
        ('function',      'S'),
        ('triggerName',   'S'),
        ('uint64_18',     'Q'),
        ('title',         'S'),
        ('str28',         'S'),
        ('flag',          'W'),   # scenario flag, set just before an _END function is called
        ('pad32',         'P6'),
        ('mapKey',        'S'),
        ('selector',      'B'),   # no triggerName: 3 = event box, 5 = look point, named by function; 4: selectorId
        ('kind',          'B'),
        ('linkedEvent',   'W'),
        ('selectorId',    'W'),
        ('pad46',         'P2'),
        ('checkFunction', 'S'),
        ('flagsSet',      'A2'),  # scenario flags that must all be set
        ('uint32_5c',     'I'),
        ('flagsClear',    'A2'),  # scenario flags none of which may be set
        ('uint32_6c',     'I'),
        ('flags',         'S'),
        ('mapEnv',        'B'),
        ('pad79',         'P7'),
    )
