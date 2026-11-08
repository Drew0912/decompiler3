from falcom.ed9.parser.tbl import TableDataEntry


# t_chapter.tbl
class ChapterParam(TableDataEntry):
    DESCRIPTOR = (
        ('key',       'I'),
        ('flagSet',   'I'),   # scenario flag that must be set; 0: the row never matches
        ('flagClear', 'I'),   # scenario flag that must be clear; 0: none
        ('eventKey',  'W'),
        ('pad0e',     'P2'),
        ('flags',     'S'),
        ('str18',     'S'),
        ('str20',     'S'),
        ('str28',     'S'),
        ('str30',     'S'),
        ('uint64_38', 'Q'),
        ('arr32_40',  'A4'),
        ('uint32_4c', 'I'),
        ('str50',     'S'),
    )
