from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_blackjack.tbl
class BlackJackMessage(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',       'W'),
        ('pad02',       'P2'),
        ('state',       'I'),
        ('text',        'S'),
        ('uint64_10',   'Q'),
        ('aniFunction', 'S'),
    )
