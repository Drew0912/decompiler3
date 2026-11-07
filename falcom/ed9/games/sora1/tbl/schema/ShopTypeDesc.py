from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class ShopTypeDesc(TableDataEntry):
    DESCRIPTOR = (
        ('id',       'W'),
        ('pad02',    'P6'),
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
