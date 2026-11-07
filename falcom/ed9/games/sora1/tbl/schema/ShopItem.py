from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class ShopItem(TableDataEntry):
    DESCRIPTOR = (
        ('shopId',     'W'),
        ('itemId',     'W'),
        ('uint8_04',   'B'),
        ('pad05',      'P3'),
        ('flagsAny',   'A2'),
        ('uint32_14',  'I'),
        ('flagsClear', 'A2'),
        ('kind',       'B'),
        ('pad25',      'P3'),
    )
