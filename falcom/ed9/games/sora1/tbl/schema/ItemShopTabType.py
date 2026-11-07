from falcom.ed9.parser.tbl import TableDataEntry


# t_item.tbl
class ItemShopTabType(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
    )
