from falcom.ed9.parser.tbl import TableDataEntry


# t_dlc.tbl
class DLCTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('arr32_08',  'A4'),
        ('uint32_14', 'I'),
        ('arr32_18',  'A4'),
        ('uint32_24', 'I'),
        ('str28',     'S'),
        ('str30',     'S'),
        ('str38',     'S'),
    )
