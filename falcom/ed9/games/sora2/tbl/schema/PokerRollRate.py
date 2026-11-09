from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_poker.tbl
class PokerRollRate(TableDataEntry):
    DESCRIPTOR = (
        ('key',            'I'),   # also the tier: rows are tried from 9 down to 1
        ('pad04',          'P4'),
        ('name',           'S'),
        ('str10',          'S'),
        ('description',    'S'),
        ('card1',          'I'),   # cardN: v % 13 and v / 13, read as rank and suit
        ('card2',          'I'),
        ('card3',          'I'),
        ('card4',          'I'),
        ('card5',          'I'),
        ('handCards',      'I'),   # the cards from this index on are dimmed; the rows' hands are their first cards
        ('rate',           'I'),   # shown as the roll's rate; not 0: the point-up effect plays
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
