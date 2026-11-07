from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotReelSpeed(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'W'),
        ('pad02',      'P2'),
        ('float32_04', 'f'),
    )
