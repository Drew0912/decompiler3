from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class MedalItem(TableDataEntry):
    DESCRIPTOR = (
        ('itemId', 'I'),
        ('price',  'I'),
    )
