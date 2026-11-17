from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_roulette.tbl
class RouletteMessage(TableDataEntry):
    DESCRIPTOR = (
        # the dealer's line for a game state; a row is found by chrId (the dealer's ID) and state together
        ('chrId',     'W'),
        ('pad02',     'P2'),
        ('state',     'I'),
        ('text',      'S'),
        ('uint64_10', 'Q'),
    )
