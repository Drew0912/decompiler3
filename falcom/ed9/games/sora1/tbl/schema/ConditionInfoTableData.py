from falcom.ed9.parser.tbl import TableDataEntry


# t_condition_info.tbl
class ConditionInfoTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',              'I'),
        ('pad04',           'P4'),
        ('name',            'S'),
        ('maxLevel',        'I'),
        ('defaultFlags',    'I'),
        ('uint32_18',       'I'),
        ('uint32_1c',       'I'),
        ('uint32_20',       'I'),
        ('uint32_24',       'I'),
        ('uint32_28',       'I'),
        ('uint32_2c',       'I'),
        ('uint32_30',       'I'),
        ('uint32_34',       'I'),
        ('uint32_38',       'I'),
        ('float32_3c',      'f'),
        ('uint32_40',       'I'),
        ('uint32_44',       'I'),
        ('linkedCondition', 'I'),
        ('pad4c',           'P4'),
        ('flags',           'S'),
    )
