from falcom.ed9.parser.tbl import TableDataEntry


# t_help.tbl
class HelpTitle(TableDataEntry):
    DESCRIPTOR = (
        ('id',       'W'),
        ('flag',     'W'),   # 0: always listed; else listed once set
        ('sortKey',  'i'),   # the help list order, ascending
        ('title',    'S'),
        ('category', 'B'),   # a NoteHelpCategory id (0 to 5; 6 and up are the tips lists)
        ('pad11',    'P7'),
    )
