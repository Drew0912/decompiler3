from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotRoles(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'W'),
        ('uint16_02', 'W'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
    )
