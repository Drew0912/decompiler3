from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class ATBonusSet(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
    )
