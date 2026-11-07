from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotInfo(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'W'),
        ('pad02',     'P2'),
        ('uint32_04', 'I'),
    )
