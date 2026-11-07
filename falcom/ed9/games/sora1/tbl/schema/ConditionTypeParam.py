from falcom.ed9.parser.tbl import TableDataEntry


# t_condition_info.tbl
class ConditionTypeParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
    )
