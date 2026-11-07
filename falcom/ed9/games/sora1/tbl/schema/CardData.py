from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_card_battler.tbl
class CardData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
    )
