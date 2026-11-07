from falcom.ed9.parser.tbl import TableDataEntry


# t_talk.tbl
class TalkTableData(TableDataEntry):
    DESCRIPTOR = (
        ('scriptArgument', 'I'),
        ('version',        'I'),
        ('mapKey',         'S'),
        ('chrId',          'W'),
        ('pad12',          'P6'),
        ('flagsSet',       'A2'),
        ('uint32_24',      'I'),
        ('flagsClear',     'A2'),
        ('uint32_34',      'I'),
        ('flagsOnChange',  'A2'),
        ('uint32_44',      'I'),
        ('arr16_48',       'A2'),
        ('uint32_54',      'I'),
    )
