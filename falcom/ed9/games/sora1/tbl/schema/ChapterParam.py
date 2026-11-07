from falcom.ed9.parser.tbl import TableDataEntry


# t_chapter.tbl
class ChapterParam(TableDataEntry):
    DESCRIPTOR = (
        ('key',       'I'),
        ('flagSet',   'I'),
        ('flagClear', 'I'),
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
