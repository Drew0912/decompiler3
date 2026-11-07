from falcom.ed9.parser.tbl import TableDataEntry


# t_condition_info.tbl
class ConditionInfoTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('uint32_10',  'I'),
        ('uint32_14',  'I'),
        ('uint32_18',  'I'),
        ('uint32_1c',  'I'),
        ('uint32_20',  'I'),
        ('uint32_24',  'I'),
        ('uint32_28',  'I'),
        ('uint32_2c',  'I'),
        ('uint32_30',  'I'),
        ('uint32_34',  'I'),
        ('uint32_38',  'I'),
        ('float32_3c', 'f'),
        ('uint64_40',  'Q'),
        ('uint64_48',  'Q'),
        ('str50',      'S'),
    )
