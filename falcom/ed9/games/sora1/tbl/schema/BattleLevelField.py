from falcom.ed9.parser.tbl import TableDataEntry


# t_btlsys.tbl
class BattleLevelField(TableDataEntry):
    DESCRIPTOR = (
        ('key',        'I'),
        ('uint32_04',  'I'),
        ('percent',    'I'),
        ('float32_0c', 'f'),
    )
