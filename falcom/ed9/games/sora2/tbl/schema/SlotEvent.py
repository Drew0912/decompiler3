from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotEvent(TableDataEntry):
    DESCRIPTOR = (
        # drawn by weight; id 1 goes on to a SlotTBoxEvent draw, 2 to a SlotBattleEvent draw
        ('id',     'W'),
        ('pad02',  'P2'),
        ('weight', 'I'),
    )
