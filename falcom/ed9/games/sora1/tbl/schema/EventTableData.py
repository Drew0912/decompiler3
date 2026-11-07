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
        ('flag',          'W'),
        ('pad32',         'P6'),
        ('mapKey',        'S'),
        ('selector',      'B'),
        ('kind',          'B'),
        ('linkedEvent',   'W'),
        ('selectorId',    'W'),
        ('pad46',         'P2'),
        ('checkFunction', 'S'),
        ('flagsSet',      'A2'),
        ('uint32_5c',     'I'),
        ('flagsClear',    'A2'),
        ('uint32_6c',     'I'),
        ('flags',         'S'),
        ('mapEnv',        'B'),
        ('pad79',         'P7'),
    )
