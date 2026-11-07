from falcom.ed9.parser.tbl import TableDataEntry


# t_item.tbl
class ItemKindParam2(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )
