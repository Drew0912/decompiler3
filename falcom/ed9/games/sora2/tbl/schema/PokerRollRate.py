from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_poker.tbl
class PokerRollRate(TableDataEntry):
    DESCRIPTOR = (
        ('key',            'I'),   # also the tier: rows are tried from 9 down to 1
        ('pad04',          'P4'),
        ('str08',          'S'),
        ('str10',          'S'),
        ('str18',          'S'),
        ('uint32_20',      'I'),
        ('uint32_24',      'I'),
        ('uint32_28',      'I'),
        ('uint32_2c',      'I'),
        ('uint32_30',      'I'),
        ('uint32_34',      'I'),
        ('uint32_38',      'I'),
        ('rollsEnabled',   'B'),
        ('pad3d',          'P3'),
        ('roll1Threshold', 'I'),   # rollN: tried when the tier's counter is above this; else, at 0, the rolls end
        ('roll1Chance',    'I'),   # percent: a roll hits when a draw from 0 to 100 is below it
        ('uint32_48',      'I'),
        ('roll2Threshold', 'I'),
        ('roll2Chance',    'I'),
        ('uint32_54',      'I'),
        ('roll3Threshold', 'I'),
        ('roll3Chance',    'I'),
        ('uint32_60',      'I'),
        ('roll4Threshold', 'I'),
        ('roll4Chance',    'I'),
        ('uint32_6c',      'I'),
        ('roll5Threshold', 'I'),
        ('roll5Chance',    'I'),
        ('uint32_78',      'I'),
        ('uint32_7c',      'I'),
    )
