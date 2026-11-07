from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_blackjack.tbl
class BlackJackHelp(TableDataEntry):
    DESCRIPTOR = (
        ('id',    'I'),
        ('pad04', 'P4'),
        ('text',  'S'),
    )
