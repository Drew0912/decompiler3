from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class ShopItem(TableDataEntry):
    DESCRIPTOR = (
        ('shopId',     'W'),
        ('itemId',     'W'),
        ('uint8_04',   'B'),
        ('pad05',      'P3'),
        ('flagsAny',   'A2'),  # one set passes, so does an empty list; a 0 is skipped
        ('uint32_14',  'I'),
        ('flagsClear', 'A2'),  # scenario flags none of which may be set; a 0 is skipped
        ('kind',       'B'),
        ('pad25',      'P3'),
    )
