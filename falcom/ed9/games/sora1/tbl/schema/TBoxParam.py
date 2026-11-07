from falcom.ed9.parser.tbl import TableDataEntry


# t_tbox.tbl
class TBoxParam(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
        ('str18',     'S'),
        ('str20',     'S'),
        ('uint64_28', 'Q'),
        ('arr16_30',  'A2'),
        ('uint32_3c', 'I'),
        ('uint64_40', 'Q'),
        ('arr16_48',  'A2'),
        ('uint32_54', 'I'),
    )
