from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class ShopItem(TableDataEntry):
    DESCRIPTOR = (
        ('shopId',     'W'),
        ('itemId',     'W'),
        # listMode: the shop's item window builds one list per mode; the row shows in this mode's list (the
        # modes a shop has: ShopTypeDesc). 0 shows in modes 1 and 9
        #   1: priced from the item's price and ShopInfo priceRate (from MedalItem in a medal shop, one with
        #   ShopTypeDesc flag M); 6, 7: checked against TradeItem's required items; 9: category 0x12 items
        #   only (0 too); 8: no list found showing it
        ('listMode',   'B'),
        ('pad05',      'P3'),
        ('flagsAny',   'A2'),  # one set passes, so does an empty list; a 0 is skipped
        ('uint32_14',  'I'),
        ('flagsClear', 'A2'),  # scenario flags none of which may be set; a 0 is skipped
        ('kind',       'B'),   # 5: a link, itemId being a shop ID (every one from 1000, none with a ShopInfo row)
        ('pad25',      'P3'),
    )
