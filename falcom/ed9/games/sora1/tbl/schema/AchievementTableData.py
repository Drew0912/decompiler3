from falcom.ed9.parser.tbl import TableDataEntry


# t_achievement.tbl
class AchievementTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint64_10', 'Q'),
        ('arr32_18',  'A4'),
        ('uint32_24', 'I'),
        ('uint32_28', 'I'),
        ('uint32_2c', 'I'),
        ('uint32_30', 'I'),
        ('uint32_34', 'I'),
        ('uint64_38', 'Q'),
        ('str40',     'S'),
        ('str48',     'S'),
        ('str50',     'S'),
        ('str58',     'S'),
    )
