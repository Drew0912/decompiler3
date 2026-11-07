from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_poker.tbl
class PokerMedal(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('uint32_20', 'I'),
        ('uint32_24', 'I'),
    )
