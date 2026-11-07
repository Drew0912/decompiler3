from falcom.ed9.parser.tbl import TableDataEntry


# t_active_voice.tbl
class ActiveVoiceTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',          'I'),
        ('group',       'B'),
        ('pad05',       'P3'),
        ('chrIds',      'A2'),
        ('uint32_14',   'I'),
        ('speaker',     'S'),
        ('kind',        'W'),
        ('pad22',       'P6'),
        ('flags',       'S'),
        ('flagsSet',    'A2'),
        ('uint32_3c',   'I'),
        ('flagsClear',  'A2'),
        ('uint32_4c',   'I'),
        ('flagsOnPlay', 'A2'),
        ('uint32_5c',   'I'),
        ('arr32_60',    'A4'),
        ('uint32_6c',   'I'),
        ('text',        'S'),
        ('float32_78',  'f'),
        ('uint32_7c',   'I'),
    )
