from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_blackjack.tbl
class BlackJackRollRate(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
        ('uint32_20', 'I'),
        ('uint32_24', 'I'),
        ('uint32_28', 'I'),
        ('uint32_2c', 'I'),
        ('uint32_30', 'I'),
        ('uint32_34', 'I'),
        ('uint32_38', 'I'),
        ('uint32_3c', 'I'),
        ('uint32_40', 'I'),
        ('uint32_44', 'I'),
        ('uint32_48', 'I'),
        ('uint32_4c', 'I'),
        ('uint32_50', 'I'),
        ('uint32_54', 'I'),
        ('uint32_58', 'I'),
        ('uint32_5c', 'I'),
        ('uint32_60', 'I'),
        ('uint32_64', 'I'),
        ('uint32_68', 'I'),
        ('uint32_6c', 'I'),
        ('uint64_70', 'Q'),
        ('uint32_78', 'I'),
        ('uint32_7c', 'I'),
    )
