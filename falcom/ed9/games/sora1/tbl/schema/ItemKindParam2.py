from falcom.ed9.parser.tbl import TableDataEntry


# t_item.tbl
class ItemKindParam2(TableDataEntry):
    DESCRIPTOR = (
        ('id',    'I'),
        ('pad04', 'P4'),
        ('name',  'S'),
    )
