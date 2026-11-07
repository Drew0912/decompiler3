from falcom.ed9.parser.tbl import TableDataEntry


# t_dlc.tbl
class DLCTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'I'),
        ('uint32_04', 'I'),
        ('itemIds',   'A4'),
        ('uint32_14', 'I'),
        ('arr32_18',  'A4'),
        ('uint32_24', 'I'),
        ('str28',     'S'),
        ('str30',     'S'),
        ('str38',     'S'),
    )
