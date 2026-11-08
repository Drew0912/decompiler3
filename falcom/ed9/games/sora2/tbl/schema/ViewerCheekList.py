from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerCheekList(TableDataEntry):
    DESCRIPTOR = (
        ('id',       'I'),
        ('pad04',    'P4'),
        ('name',     'S'),
        ('commands', 'S'),   # #-codes such as #E_0#M_0#B_0; nothing is read unless it starts with #
    )
