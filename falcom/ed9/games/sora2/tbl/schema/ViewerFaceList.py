from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerFaceList(TableDataEntry):
    DESCRIPTOR = (
        ('id',       'I'),
        ('pad04',    'P4'),
        ('name',     'S'),
        ('str10',    'S'),
        ('str18',    'S'),
        ('uint8_20', 'B'),
        ('pad21',    'P7'),
        ('flags',    'S'),
    )
