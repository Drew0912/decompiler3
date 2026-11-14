from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class CharaSettingInfo(TableDataEntry):
    DESCRIPTOR = (
        # a row is kept when this is 2 for a count of 1, 1 for a count of 3 or more, else 0 (what is counted:
        # not known); the values 2, 0, 1 have 1, 2, 3 rows
        ('uint16_00',  'W'),
        ('pad02',      'P2'),
        ('float32_04', 'f'),
        ('float32_08', 'f'),
        ('float32_0c', 'f'),
        ('float32_10', 'f'),
    )
