from falcom.ed9.parser.tbl import TableDataEntry


# t_field_item.tbl
class FieldItemTableData(TableDataEntry):
    DESCRIPTOR = (
        ('mapKey',    'S'),
        ('x',         'f'),
        ('y',         'f'),
        ('z',         'f'),
        ('flagSet',   'W'),
        ('flagClear', 'W'),
        ('takenFlag', 'W'),
        ('itemId',    'W'),
        ('amount',    'W'),
        ('pad1e',     'P2'),
    )
