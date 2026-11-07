from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_card_battler.tbl
class CardBattlerMessage(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('uint32_04',  'I'),
        ('str08',      'S'),
        ('uint32_10',  'I'),
        ('float32_14', 'f'),
    )
