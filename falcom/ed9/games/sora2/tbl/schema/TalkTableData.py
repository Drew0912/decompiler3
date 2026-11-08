from falcom.ed9.parser.tbl import TableDataEntry


# t_talk.tbl
class TalkTableData(TableDataEntry):
    DESCRIPTOR = (
        ('scriptArgument', 'I'),
        ('version',        'I'),
        ('mapKey',         'S'),
        ('chrId',          'W'),   # 0xFFFF: any
        ('pad12',          'P6'),
        ('flagsSet',       'A2'),  # scenario flags that must all be set
        ('uint32_24',      'I'),
        ('flagsClear',     'A2'),  # scenario flags none of which may be set
        ('uint32_34',      'I'),
        ('flagsOnChange',  'A2'),  # scenario flags set when the talk changes
        ('uint32_44',      'I'),
        ('arr16_48',       'A2'),
        ('uint32_54',      'I'),
    )
