from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_fishing.tbl
class FishingRodInfo(TableDataEntry):
    DESCRIPTOR = (
        ('itemId',      'I'),
        ('bait1',       'I'),
        ('bait2',       'I'),
        ('bait3',       'I'),
        ('bait4',       'I'),
        ('bait5',       'I'),
        ('bait6',       'I'),
        ('bait7',       'I'),
        ('bait8',       'I'),
        ('bait9',       'I'),
        ('bait10',      'I'),
        ('bait11',      'I'),
        ('bait12',      'I'),
        ('bait13',      'I'),
        ('bait14',      'I'),
        ('bait15',      'I'),
        ('bait16',      'I'),
        ('bait17',      'I'),
        ('bait18',      'I'),
        ('float32_4c',  'f'),  # not read from the row: with no row for the rod, the exe reads the address 0x4C instead
        # gainFactorN: scales the gauge's gain (FishingConstant gaugeGain) for a fish of FishInfo sizeClass N
        ('gainFactor0', 'f'),
        ('gainFactor1', 'f'),
        ('gainFactor2', 'f'),
        ('gainFactor3', 'f'),
    )
