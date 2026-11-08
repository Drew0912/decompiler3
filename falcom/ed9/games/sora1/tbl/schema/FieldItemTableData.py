from falcom.ed9.parser.tbl import TableDataEntry


# t_field_item.tbl
class FieldItemTableData(TableDataEntry):
    DESCRIPTOR = (
        ('mapKey',    'S'),
        ('x',         'f'),
        ('y',         'f'),
        ('z',         'f'),
        ('flagSet',   'W'),   # scenario flag that must be set; 0: none
        ('flagClear', 'W'),   # scenario flag that must be clear; 0: none
        ('takenFlag', 'W'),   # scenario flag: the row is skipped if set; set on the row chosen
        ('itemId',    'W'),
        ('amount',    'W'),
        ('pad1e',     'P2'),
    )
