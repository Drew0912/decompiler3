from falcom.ed9.parser.tbl import TableDataEntry


# t_uds.tbl
class UDSActivityData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )
