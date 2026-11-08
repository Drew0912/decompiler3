from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_blackjack.tbl
class BlackJackRollRate(TableDataEntry):
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
        ('uint32_3c',      'I'),
        ('rollsEnabled',   'B'),
        ('uint8_41',       'B'),
        ('pad42',          'P2'),
        ('roll1Threshold', 'I'),   # rollN: tried when the tier's counter is above this; else, at 0, the rolls end
        ('roll1Chance',    'I'),   # percent: a roll hits when a draw from 0 to 100 is below it
        ('uint32_4c',      'I'),
        ('roll2Threshold', 'I'),
        ('roll2Chance',    'I'),
        ('uint32_58',      'I'),
        ('roll3Threshold', 'I'),
        ('roll3Chance',    'I'),
        ('uint32_64',      'I'),
        ('roll4Threshold', 'I'),
        ('roll4Chance',    'I'),
        ('uint32_70',      'I'),
        ('roll5Threshold', 'I'),
        ('roll5Chance',    'I'),
        ('uint32_7c',      'I'),
    )
