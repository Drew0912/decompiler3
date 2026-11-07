from falcom.ed9.parser.tbl import TableDataEntry


# t_achievement.tbl
class AchievementCategoryData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )
