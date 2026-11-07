from falcom.ed9.parser.tbl import TableDataEntry


# t_achievement.tbl
class PlayRecordData(TableDataEntry):
    DESCRIPTOR = (
        ('uint8_00', 'B'),
        ('pad01',    'P7'),
        ('flags',    'S'),
        ('text',     'S'),
        ('str18',    'S'),
        ('str20',    'S'),
    )
