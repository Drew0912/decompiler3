from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotReelPattern(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint16_04', 'W'),
    )
