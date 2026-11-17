from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotBattleEvent(TableDataEntry):
    DESCRIPTOR = (
        # drawn by weight; id: the SlotMonsterInfo key of the monster that appears (id 0, None, has weight 0)
        ('id',     'W'),
        ('pad02',  'P2'),
        ('weight', 'I'),
    )
