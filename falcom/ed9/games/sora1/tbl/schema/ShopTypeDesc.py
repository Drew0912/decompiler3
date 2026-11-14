from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class ShopTypeDesc(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'W'),
        ('pad02',     'P6'),
        # flags, a bit per letter:
        #   M 0x10: tested by the shop menus, the medal exchange among them
        #   E 0x1, B 0x2, K 0x4, P 0x8: nothing found reading it
        ('flags',     'S'),
        # listMode1..listMode7: the ShopItem listMode values the shop accepts, read up to the first 0 (a
        # ShopItem row with 0 always passes; in a medal shop, one with flag M, 7 stands for 1); the first
        # goes to the code opening the item window. 2: a list built from the item table, not from ShopItem
        # rows. 3, 4, 12, 13 and the 100 ending each list: nothing found handling them
        ('listMode1', 'B'),
        ('listMode2', 'B'),
        ('listMode3', 'B'),
        ('listMode4', 'B'),
        ('listMode5', 'B'),
        ('listMode6', 'B'),
        ('listMode7', 'B'),
        ('pad17',     'P1'),
    )
