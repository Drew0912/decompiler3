from falcom.ed9.parser.tbl import TableDataEntry


# t_condition_info.tbl
class OverDriveEffect(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',        'I'),
        ('effect1Type',  'I'),
        ('effect1Value', 'I'),
        ('effect2Type',  'I'),
        ('effect2Value', 'I'),
        ('effect3Type',  'I'),
        ('effect3Value', 'I'),
        ('effect4Type',  'I'),
        ('effect4Value', 'I'),
        ('effect5Type',  'I'),
        ('effect5Value', 'I'),
        ('pad2c',        'P4'),
        ('ability1',     'S'),
        ('ability2',     'S'),
        ('ability3',     'S'),
        ('ability4',     'S'),
        ('ability5',     'S'),
        ('ability6',     'S'),
        ('str60',        'S'),
    )
