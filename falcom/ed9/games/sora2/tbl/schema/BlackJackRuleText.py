from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_blackjack.tbl
class BlackJackRuleText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )
