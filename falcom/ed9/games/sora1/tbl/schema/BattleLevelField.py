from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class BattleLevelField(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('uint32_04',  'I'),
        ('uint32_08',  'I'),
        ('float32_0c', 'f'),
    )
