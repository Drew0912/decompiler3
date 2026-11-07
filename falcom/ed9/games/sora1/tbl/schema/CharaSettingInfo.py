from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class CharaSettingInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('float32_04', 'f'),
        ('float32_08', 'f'),
        ('float32_0c', 'f'),
        ('float32_10', 'f'),
    )
