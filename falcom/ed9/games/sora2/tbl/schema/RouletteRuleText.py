from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_roulette.tbl
class RouletteRuleText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),   # 1 to N in row order; not read
        ('text',      'S'),   # a page of the rules window; the row count is the page count
        ('hasNumber', 'B'),   # not 0: text is a format; %s is RouletteInfo spotChipLimit (first page only)
        ('pad11',     'P7'),
    )
