from falcom.ed9.parser.tbl import TableDataEntry


# t_itemhelp.tbl
class ItemKindHelpData(TableDataEntry):
    DESCRIPTOR = (
        ('category',    'W'),
        ('subcategory', 'W'),
        ('uint32_04',   'I'),
        ('str08',       'S'),
        ('uint32_10',   'I'),
        ('pad14',       'P4'),
        ('name',        'S'),
    )
