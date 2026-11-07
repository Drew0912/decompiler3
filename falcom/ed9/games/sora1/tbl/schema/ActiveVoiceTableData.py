from falcom.ed9.parser.tbl import TableDataEntry


# t_active_voice.tbl
class ActiveVoiceTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('arr16_08',  'A2'),
        ('uint32_14', 'I'),
        ('str18',     'S'),
        ('uint64_20', 'Q'),
        ('str28',     'S'),
        ('arr16_30',  'A2'),
        ('uint32_3c', 'I'),
        ('arr16_40',  'A2'),
        ('uint32_4c', 'I'),
        ('arr16_50',  'A2'),
        ('uint32_5c', 'I'),
        ('arr32_60',  'A4'),
        ('uint32_6c', 'I'),
        ('str70',     'S'),
        ('uint32_78', 'I'),
        ('uint32_7c', 'I'),
    )
