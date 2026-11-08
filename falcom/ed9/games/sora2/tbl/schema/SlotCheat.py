from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotCheat(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint16_08', 'W'),   # row 0 only; 5 or less: also a SlotTBoxInfo key
        ('pad0a',     'P2'),
    )
