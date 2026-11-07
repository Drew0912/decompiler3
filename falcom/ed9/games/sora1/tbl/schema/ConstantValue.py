from falcom.ed9.parser.tbl import TableDataEntry


# t_constant_value.tbl
class ConstantValue(TableDataEntry):
    DESCRIPTOR = (
        ('index',  'I'),
        ('value',  'i'),
        ('value2', 'i'),
    )
