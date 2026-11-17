from falcom.ed9.parser.tbl import TableDataEntry


# t_title.tbl
class TitleTableData(TableDataEntry):
    DESCRIPTOR = (
        # matched with a save byte; for 3 the exe also passes system/title_clear, else system/title_sub (call not read)
        ('groupKey',   'W'),
        ('pad02',      'P6'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('image',      'S'),
        ('bgmId',      'I'),
        ('float32_24', 'f'),
        ('video',      'S'),   # a webm, played after idleTime without input, by its use; empty: none
        ('idleTime',   'f'),   # seconds without input before the video plays, by its use
        ('uint32_34',  'I'),
    )
