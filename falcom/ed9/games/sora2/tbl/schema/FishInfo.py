from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_fishing.tbl
class FishInfo(TableDataEntry):
    DESCRIPTOR = (
        ('id',            'W'),
        ('saveIndex',     'W'),
        ('sizeClass',     'W'),   # 0 small, 1 middle, 2 and 3 large
        ('pad06',         'P2'),
        ('str08',         'S'),
        ('rewardItem1',   'I'),
        ('rewardItem2',   'I'),
        ('rewardItem3',   'I'),
        ('rewardCount1',  'I'),
        ('rewardCount2',  'I'),
        ('rewardCount3',  'I'),
        ('sepith1Earth',  'I'),   # sepithN*: added to the save's sepith, at most 99999; N pairs with rewardItemN
        ('sepith1Water',  'I'),
        ('sepith1Fire',   'I'),
        ('sepith1Wind',   'I'),
        ('sepith1Time',   'I'),
        ('sepith1Space',  'I'),
        ('sepith1Mirage', 'I'),
        ('sepith1Mass',   'I'),
        ('sepith2Earth',  'I'),
        ('sepith2Water',  'I'),
        ('sepith2Fire',   'I'),
        ('sepith2Wind',   'I'),
        ('sepith2Time',   'I'),
        ('sepith2Space',  'I'),
        ('sepith2Mirage', 'I'),
        ('sepith2Mass',   'I'),
        ('sepith3Earth',  'I'),
        ('sepith3Water',  'I'),
        ('sepith3Fire',   'I'),
        ('sepith3Wind',   'I'),
        ('sepith3Time',   'I'),
        ('sepith3Space',  'I'),
        ('sepith3Mirage', 'I'),
        ('sepith3Mass',   'I'),
        ('sizeMax',       'f'),
        ('sizeMin',       'f'),
        # gauge: a bar the rod fills (FishingConstant gaugeGain) and the fish drains, by its use
        ('gaugeDrain',    'f'),   # taken off the gauge, times the frame time
        ('gaugeDrain2',   'f'),   # as gaugeDrain, on the other branch of one test
        # a countdown's start (a reading); one path adds a draw up to FishingConstant countdownSpread; it runs
        # out only while the gauge is between 0 and gaugeMax, and then the fishing state changes
        ('countdown',     'f'),
        ('gaugeMax',      'f'),   # the gauge's cap: reaching it, or 0, ends the struggle, by its use
        ('baseSize',      'f'),   # the fish's size divided by it gives a scale (a reading)
        ('float32_a4',    'f'),
        ('angle',         'f'),   # degrees
        ('float32_ac',    'f'),
        ('float32_b0',    'f'),
        ('float32_b4',    'f'),
        ('float32_b8',    'f'),
        ('float32_bc',    'f'),
        ('float32_c0',    'f'),   # the upper bound of a draw stored in each fish slot entry; use not traced
        ('float32_c4',    'f'),
        ('timerMax',      'f'),   # a fish's timer restarts at a random value from 0.5 up to this
        ('yaw',           'f'),   # degrees: the middle one of three angles (0, yaw, 0)
        ('text',          'S'),
        ('uint8_d8',      'B'),
        ('padd9',         'P7'),
    )
