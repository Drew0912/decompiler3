from falcom.ed9.parser.tbl import TableDataEntry


# t_voice.tbl
class VoiceTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('uint32_10',  'I'),
        ('float32_14', 'f'),
        ('uint32_18',  'I'),
        ('float32_1c', 'f'),
        ('str20',      'S'),
    )
