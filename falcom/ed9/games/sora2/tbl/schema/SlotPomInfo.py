from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotPomInfo(TableDataEntry):
    DESCRIPTOR = (
        ('id',              'W'),
        ('pad02',           'P6'),
        ('name',            'S'),   # empty: hidden, by its use
        ('hp',              'I'),   # lowered by SlotMonsterInfo attack; shown as a gauge
        ('attack',          'I'),   # taken off SlotMonsterInfo hp; doubled by doubleThreshold
        ('bonusId',         'I'),
        ('doubleThreshold', 'w'),   # attack doubles when one of up to five reel values (a reading) is 0 to this
        ('pad1e',           'P2'),
    )
