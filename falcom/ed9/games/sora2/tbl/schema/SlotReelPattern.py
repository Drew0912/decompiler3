from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotReelPattern(TableDataEntry):
    DESCRIPTOR = (
        ('column0', 'W'),
        ('column1', 'W'),
        ('column2', 'W'),
    )
