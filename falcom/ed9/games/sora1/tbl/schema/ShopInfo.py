from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class ShopInfo(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'W'),
        ('pad02',      'P6'),
        ('name',       'S'),
        ('shopType',   'B'),
        ('pad11',      'P7'),
        ('flags',      'S'),
        ('convId',     'B'),
        ('pad21',      'P1'),
        ('priceRate',  'H'),
        ('float32_24', 'f'),
        ('float32_28', 'f'),
        ('float32_2c', 'f'),
        ('float32_30', 'f'),
        ('float32_34', 'f'),
        ('uint32_38',  'I'),
        ('float32_3c', 'f'),
        ('float32_40', 'f'),
        ('voiceId',    'I'),
    )
