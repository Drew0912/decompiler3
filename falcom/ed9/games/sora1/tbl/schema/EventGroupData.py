from falcom.ed9.parser.tbl import TableDataEntry


# t_evtable.tbl
class EventGroupData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )
