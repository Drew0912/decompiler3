from falcom.ed9.parser.tbl import TableDataEntry


# t_condition_info.tbl
class ConditionTypeParam(TableDataEntry):
    DESCRIPTOR = (
        ('conditionId', 'B'),
        ('pad01',       'P3'),
        ('listIndex',   'B'),
        ('pad05',       'P3'),
    )
