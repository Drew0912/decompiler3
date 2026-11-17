from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_fishing.tbl
class OutItemList(TableDataEntry):
    DESCRIPTOR = (
        ('key',     'I'),  # the fish slot's kind, as in FishingConstant outItemChanceN
        # itemN, countN, weightN: one entry is drawn by weight; nothing found reading countN
        ('item1',   'I'),
        ('count1',  'I'),
        ('weight1', 'I'),
        ('item2',   'I'),
        ('count2',  'I'),
        ('weight2', 'I'),
        ('item3',   'I'),
        ('count3',  'I'),
        ('weight3', 'I'),
        ('item4',   'I'),
        ('count4',  'I'),
        ('weight4', 'I'),
        ('item5',   'I'),
        ('count5',  'I'),
        ('weight5', 'I'),
    )
