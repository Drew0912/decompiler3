from falcom.ed9.parser.tbl import TableDataEntry


# t_tbox.tbl
class TBoxParam(TableDataEntry):
    DESCRIPTOR = (
        ('mapKey',    'S'),
        ('name',      'S'),
        ('uint64_10', 'Q'),
        ('flags',     'S'),
        ('str20',     'S'),
        ('uint64_28', 'Q'),
        ('arr16_30',  'A2'),
        ('uint32_3c', 'I'),
        ('uint64_40', 'Q'),
        ('arr16_48',  'A2'),
        ('uint32_54', 'I'),
    )
