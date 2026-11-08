from falcom.ed9.parser.tbl import TableDataEntry


# t_active_voice.tbl
class ActiveVoiceTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',          'I'),   # 0: none; rows of one ID play in order
        ('group',       'B'),
        ('pad05',       'P3'),
        ('chrIds',      'A2'),
        ('uint32_14',   'I'),
        ('speaker',     'S'),
        ('kind',        'W'),   # 0: plays once only; 1: a battle talk sound
        ('pad22',       'P6'),
        ('flags',       'S'),
        ('flagsSet',    'A2'),  # plays only if all of these scenario flags are set; a 0 is skipped
        ('uint32_3c',   'I'),
        ('flagsClear',  'A2'),  # plays only if none of these scenario flags are set
        ('uint32_4c',   'I'),
        ('flagsOnPlay', 'A2'),  # won't play if all are already set; then set at the start, or at the end if flags has D
        ('uint32_5c',   'I'),
        ('voiceIds',    'A4'),  # paired with chrIds by position when both have the same count
        ('uint32_6c',   'I'),
        ('text',        'S'),
        ('float32_78',  'f'),
        ('uint32_7c',   'I'),
    )
