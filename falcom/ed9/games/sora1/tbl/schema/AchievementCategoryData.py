from falcom.ed9.parser.tbl import TableDataEntry


# t_achievement.tbl
class AchievementCategoryData(TableDataEntry):
    DESCRIPTOR = (
        ('id',    'B'),
        ('pad01', 'P7'),
        ('text',  'S'),
    )
