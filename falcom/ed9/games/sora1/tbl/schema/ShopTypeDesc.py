from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class ShopTypeDesc(TableDataEntry):
    DESCRIPTOR = (
        ('id',       'W'),
        ('pad02',    'P6'),
        # flags, a bit per letter:
        #   M 0x10: tested by the shop menus, the medal exchange among them
        #   E 0x1, B 0x2, K 0x4, P 0x8: nothing found reading it
        ('flags',    'S'),
        ('uint8_10', 'B'),
        ('uint8_11', 'B'),
        ('uint8_12', 'B'),
        ('uint8_13', 'B'),
        ('uint8_14', 'B'),
        ('uint8_15', 'B'),
        ('uint8_16', 'B'),
        ('pad17',    'P1'),
    )
