from falcom.ed9.parser.tbl import TableDataEntry


# t_tbox.tbl
class TBoxParam(TableDataEntry):
    DESCRIPTOR = (
        ('mapKey',     'S'),
        ('name',       'S'),
        ('uint64_10',  'Q'),
        # flags, a bit per letter:
        #   N 0x2: never found by the lookup by mapKey and name
        #   M 0x4: uses the script function tbox.AniWaitMonster instead of tbox.AniWait; also looks up the script
        #     function named in function
        #   D 0x80000000: left out of the count of rows whose scenario flag (0xA8C + row index) is set;
        #     scripts get that count
        #   V 0x8: read by code, purpose not known
        #   R 0x1: nothing found reading it
        ('flags',      'S'),
        ('function',   'S'),
        ('flag1',      'W'),
        ('flag2',      'W'),
        ('pad2c',      'P4'),
        ('items',      'A2'),
        ('uint32_3c',  'I'),
        ('altFlag',    'W'),   # scenario flag; once set, altItems and uint32_54 replace items and uint32_3c; 0: none
        ('pad42',      'P6'),
        ('altItems',   'A2'),
        ('uint32_54',  'I'),
        ('flagsSet',   'A2'),  # scenario flags that must all be set
        ('uint32_64',  'I'),
        ('flagsClear', 'A2'),  # scenario flags none of which may be set
        ('uint32_74',  'I'),
    )
