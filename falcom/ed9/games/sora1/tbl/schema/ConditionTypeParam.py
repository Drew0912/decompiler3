from falcom.ed9.parser.tbl import TableDataEntry


# t_condition_info.tbl
class ConditionTypeParam(TableDataEntry):
    DESCRIPTOR = (
        ('conditionId', 'I'),
        ('listIndex',   'I'),
    )
