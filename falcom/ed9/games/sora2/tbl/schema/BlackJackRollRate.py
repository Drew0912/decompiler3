from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_blackjack.tbl
class BlackJackRollRate(TableDataEntry):
    DESCRIPTOR = (
        ('key',            'I'),   # also the tier: rows are tried from 9 down to 1
        ('pad04',          'P4'),
        ('name',           'S'),
        ('str10',          'S'),
        ('description',    'S'),
        ('card1',          'i'),   # cardN: v % 13 and v / 13, read as rank and suit; -1: no card
        ('card2',          'i'),
        ('card3',          'i'),
        ('card4',          'i'),
        ('card5',          'i'),
        ('card6',          'i'),
        ('card7',          'i'),
        ('rate',           'I'),   # shown as the roll's rate; not 0: the point-up effect plays
        ('rollsEnabled',   'B'),
        ('cardsShown',     'B'),   # 0: the card widgets are cleared, as for a card of -1
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
