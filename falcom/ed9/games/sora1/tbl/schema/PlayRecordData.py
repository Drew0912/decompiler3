from falcom.ed9.parser.tbl import TableDataEntry


# t_achievement.tbl
class PlayRecordData(TableDataEntry):
    DESCRIPTOR = (
        ('uint8_00', 'B'),
        ('pad01',    'P7'),
        # flags, 1 when it holds H, else 0 (not a mask):
        #   H: nothing found reading it
        ('flags',    'S'),
        ('text',     'S'),
        ('str18',    'S'),
        ('str20',    'S'),
    )
