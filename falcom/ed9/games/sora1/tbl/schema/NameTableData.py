from falcom.ed9.parser.tbl import TableDataEntry


# t_name.tbl
class NameTableData(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',            'W'),
        ('pad02',            'P6'),
        ('chrName',          'S'),
        ('model',            'S'),
        ('face',             'S'),
        ('ani',              'S'),
        ('uint32_28',        'I'),
        ('pad2c',            'P4'),
        ('flags',            'S'),
        ('saveIndex',        'B'),   # 1 to 0x63; 0: none
        ('pad39',            'P7'),
        ('statusKey',        'S'),
        ('scenarioFlag',     'W'),   # 0: none
        ('pad4a',            'P6'),
        ('flaggedStatusKey', 'S'),
        ('str58',            'S'),
        ('str60',            'S'),
    )
