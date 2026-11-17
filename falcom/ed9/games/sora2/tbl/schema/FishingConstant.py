from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_fishing.tbl
class FishingConstant(TableDataEntry):
    DESCRIPTOR = (
        ('objectId',        'W'),
        ('pad02',           'P2'),
        ('countdownSpread', 'f'),   # the upper bound of a draw added to FishInfo countdown on one code path
        ('gaugeGain',       'f'),   # added to the gauge, times the frame time and FishingRodInfo gainFactorN
        ('float32_0c',      'f'),
        ('float32_10',      'f'),
        ('float32_14',      'f'),
        ('float32_18',      'f'),
        ('float32_1c',      'f'),
        ('float32_20',      'f'),
        ('float32_24',      'f'),
        # outItemChanceN: percent (a reading), by the kind of the fish slot (a number per slot, 0 to 3; 3 uses
        # outItemChance2): a hit draws from that OutItemList key, and the gauge then gains gaugeGain / 2 in
        # place of the drain and the countdown
        ('outItemChance0',  'f'),
        ('outItemChance1',  'f'),
        ('outItemChance2',  'f'),
        ('float32_34',      'f'),
        ('float32_38',      'f'),
        ('float32_3c',      'f'),
        ('float32_40',      'f'),
        ('float32_44',      'f'),   # copied to each of 15 fish objects; use not traced
        ('float32_48',      'f'),
        ('range',           'f'),   # a distance limit, by its use: past it a fish slot's flag is cleared
        ('uint32_50',       'I'),
        ('uint32_54',       'I'),
        ('str58',           'S'),
    )
