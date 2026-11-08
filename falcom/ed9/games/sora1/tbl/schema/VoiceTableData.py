from falcom.ed9.parser.tbl import TableDataEntry


# t_voice.tbl
class VoiceTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'I'),   # rows sorted by it at load
        ('pad04',      'P4'),
        ('name',       'S'),
        ('uint8_10',   'B'),
        ('pad11',      'P3'),
        ('float32_14', 'f'),
        ('uint16_18',  'W'),
        ('pad1a',      'P2'),
        ('float32_1c', 'f'),
        ('transcript', 'S'),
    )
