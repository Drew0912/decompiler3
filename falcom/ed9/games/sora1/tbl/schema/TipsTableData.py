from falcom.ed9.parser.tbl import TableDataEntry


# t_tips.tbl
class TipsTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'W'),
        ('uint16_02',  'W'),   # scenario flag minus 0x1CE8; set once the tip is shown, by its use
        ('flag',       'W'),   # scenario flag that must be set; 0: none
        ('pad06',      'P2'),
        ('flagsClear', 'A2'),  # scenario flags none of which may be set
        ('uint16_14',  'W'),
        ('pad16',      'P2'),
        # flags, a bit per letter:
        #   R 0x1: not listed until the scenario flag in uint16_02 (stored as flag minus 0x1CE8) is set
        #   N 0x2: left out of the tips lists
        #   P 0x4: nothing found reading it
        ('flags',      'S'),
        ('category',   'B'),   # a NoteHelpCategory id (6 and up: the tips lists)
        ('pad21',      'P3'),
        ('sortKey',    'i'),   # the tips list order, ascending
        ('title',      'S'),
        ('text',       'S'),
    )
