from falcom.ed9.parser.tbl import TableDataEntry


# t_btl_voice.tbl
class BTLVoiceTable(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('arr16_10',  'A2'),
        ('uint32_1c', 'I'),
        ('arr16_20',  'A2'),
        ('uint32_2c', 'I'),
        ('arr32_30',  'A4'),
        ('uint32_3c', 'I'),
        ('str40',     'S'),
        ('arr8_48',   'A1'),
        ('uint32_54', 'I'),
    )
