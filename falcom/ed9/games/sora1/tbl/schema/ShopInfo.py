from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class ShopInfo(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'W'),
        ('pad02',      'P6'),
        ('name',       'S'),
        ('shopType',   'B'),   # a ShopTypeDesc id
        ('pad11',      'P7'),
        # flags, 1 when it holds C, else 0 (not a mask):
        #   C: the script functions OnTalkBeginCam and OnTalkEndCam (script system) treat the shop as an ordinary
        #     conversation, not a shop (no shop camera, menu or closing step)
        ('flags',      'S'),
        ('convId',     'B'),
        ('pad21',      'P1'),
        ('priceRate',  'H'),   # percent, by its use: item price * priceRate / 100, rounded up
        ('float32_24', 'f'),
        ('float32_28', 'f'),
        ('float32_2c', 'f'),
        ('float32_30', 'f'),
        ('float32_34', 'f'),
        ('uint32_38',  'I'),
        ('float32_3c', 'f'),
        ('float32_40', 'f'),
        ('voiceId',    'I'),   # 0: none
    )
