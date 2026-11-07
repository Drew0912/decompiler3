from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotReelSpeed(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('float32_04', 'f'),
    )
