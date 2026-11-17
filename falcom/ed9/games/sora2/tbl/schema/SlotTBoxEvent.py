from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotTBoxEvent(TableDataEntry):
    DESCRIPTOR = (
        # drawn by weight; id: the SlotTBoxInfo key (SlotPomInfo bonusId can rule some out, at times)
        ('id',     'W'),
        ('pad02',  'P2'),
        ('weight', 'I'),
    )
