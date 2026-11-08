from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotTBoxInfo(TableDataEntry):
    DESCRIPTOR = (
        ('key',       'W'),
        ('pad02',     'P2'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('weight1',   'I'),   # weightN goes with uint32_0c to uint32_1c in order, for a draw below their sum
        ('weight2',   'I'),
        ('weight3',   'I'),
        ('weight4',   'I'),
        ('weight5',   'I'),
    )
