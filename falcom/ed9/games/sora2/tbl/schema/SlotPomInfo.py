from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotPomInfo(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'W'),
        ('pad02',     'P6'),
        ('name',      'S'),   # empty: hidden, by its use
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('bonusId',   'I'),
        ('uint32_1c', 'I'),
    )
