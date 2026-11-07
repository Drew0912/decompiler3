from falcom.ed9.parser.tbl import TableDataEntry


# t_itemhelp.tbl
class SkillRangeData(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'W'),
        ('pad02',      'P2'),
        ('thresholdS', 'f'),
        ('thresholdM', 'f'),
        ('thresholdL', 'f'),
        ('float32_10', 'f'),
    )
