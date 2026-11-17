from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotMonsterInfo(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'W'),
        ('pad02',     'P6'),
        ('name',      'S'),
        ('hp',        'I'),   # lowered by SlotPomInfo attack; shown as a gauge
        ('attack',    'I'),   # taken off SlotPomInfo hp
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('uint32_20', 'I'),
        ('weight1',   'I'),   # weightN goes with uint32_18, uint32_1c, uint32_20 in order; a draw from 0 to 99
        ('weight2',   'I'),
        ('weight3',   'I'),
    )
