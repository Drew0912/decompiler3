from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
    )
