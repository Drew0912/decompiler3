from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class TradeItem(TableDataEntry):
    DESCRIPTOR = (
        ('itemId',    'I'),
        ('item1',     'I'),
        ('uint32_08', 'I'),
        ('item2',     'I'),
        ('uint32_10', 'I'),
        ('item3',     'I'),
        ('uint32_18', 'I'),
        ('item4',     'I'),
        ('uint32_20', 'I'),
        ('item5',     'I'),
        ('uint32_28', 'I'),
        ('item6',     'I'),
        ('uint32_30', 'I'),
    )
