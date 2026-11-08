from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotInfo(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'W'),
        ('pad02',      'P2'),
        ('multiplier', 'I'),   # times each SlotRoles' uint32_08, shown as the number
    )
