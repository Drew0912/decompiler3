from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class ATBonusParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('str20',     'S'),
    )
