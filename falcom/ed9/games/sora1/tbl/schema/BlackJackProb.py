from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_blackjack.tbl
class BlackJackProb(TableDataEntry):
    DESCRIPTOR = (
        # weightN: percent chance that the dealer plays as class N, in a row drawn at random; class 0 always
        # goes bust (except at the deck's end), 1 to 5 stop on exactly 16 + N, 6 depends on which of two callers
        # runs it
        ('weight0', 'I'),
        ('weight1', 'I'),
        ('weight2', 'I'),
        ('weight3', 'I'),
        ('weight4', 'I'),
        ('weight5', 'I'),
        ('weight6', 'I'),
    )
