from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_roulette.tbl
class RouletteBetRate(TableDataEntry):
    DESCRIPTOR = (
        ('id',           'I'),
        ('pad04',        'P4'),
        ('oddsText',     'S'),   # the result list's odds text; the same as name on every row
        ('name',         'S'),
        # a payout rate (a reading): shown on the bet line; the result list shows rate * 10 per bet of this kind
        ('rate',         'I'),
        # cheatEnabled: not 0 lets a bet of this kind set off the cheat once RouletteCheat's value is 100;
        # cheatChance: percent chance it then goes off; the round lands on one of the bet's numbers (a reading)
        ('cheatEnabled', 'B'),
        ('pad1d',        'P3'),
        ('cheatChance',  'I'),
        ('uint32_24',    'I'),
    )
