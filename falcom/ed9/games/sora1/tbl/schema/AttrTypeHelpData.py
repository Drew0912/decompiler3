from falcom.ed9.parser.tbl import TableDataEntry


# t_itemhelp.tbl
class AttrTypeHelpData(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'W'),
        ('pad02',     'P6'),
        ('name',      'S'),
        ('uint16_10', 'W'),
        ('pad12',     'P6'),
    )
