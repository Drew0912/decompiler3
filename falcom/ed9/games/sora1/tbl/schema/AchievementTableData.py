from falcom.ed9.parser.tbl import TableDataEntry


# t_achievement.tbl
class AchievementTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',   'I'),
        ('saveIndex',   'I'),
        ('workIndex',   'I'),
        ('target',      'i'),
        ('cap',         'i'),
        ('pad14',       'P4'),
        ('arr32_18',    'A4'),
        ('flag',        'W'),
        ('uint8_26',    'B'),
        ('pad27',       'P1'),
        ('itemId',      'W'),
        ('altItemId',   'W'),
        ('amount',      'I'),
        ('altAmount',   'I'),
        ('item2Id',     'W'),
        ('pad36',       'P2'),
        ('amount2',     'I'),
        ('pad3c',       'P4'),
        ('flags',       'S'),
        ('name',        'S'),
        ('description', 'S'),
        ('str58',       'S'),
    )
