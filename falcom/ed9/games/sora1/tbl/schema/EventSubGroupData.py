from falcom.ed9.parser.tbl import TableDataEntry


# t_evtable.tbl
class EventSubGroupData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )
