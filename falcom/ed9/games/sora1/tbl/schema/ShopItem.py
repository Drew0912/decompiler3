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
        ('kind',       'B'),   # 5: a link, itemId being a shop ID (every one from 1000, none with a ShopInfo row)
        ('pad25',      'P3'),
    )
