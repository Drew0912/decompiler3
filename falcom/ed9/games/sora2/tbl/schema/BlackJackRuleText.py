from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_blackjack.tbl
class BlackJackRuleText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),   # 1 to N in row order; not read
        ('text',      'S'),   # a page of the rules window; the row count is the page count
        # hasNumber not 0: text is a format whose %s is BlackJackInfo row 0's defaultValue, or its value1 /
        # value2 when flag1 / flag2 is set
        ('hasNumber', 'B'),
        ('pad11',     'P7'),
    )
