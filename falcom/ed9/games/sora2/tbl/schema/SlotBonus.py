from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotBonus(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'W'),
        ('pad02',     'P2'),
        ('iconIndex', 'I'),   # 1 to 6: one of six cells of a 3-by-2 icon grid (a reading); else the first cell
        # a turn count, by its use; not 0: gates SlotTBoxEvent's filter and a forced SlotTBoxInfo key 5
        ('turns',     'I'),
    )
