from falcom.ed9.parser.tbl import TableDataEntry


# t_orbment.tbl
class QuartzParam(TableDataEntry):
    DESCRIPTOR = (
        ('itemId',       'W'),
        ('family',       'B'),
        ('pad03',        'P5'),
        ('flags',        'S'),
        ('minSlotLevel', 'W'),
        ('uint16_12',    'W'),
        ('uint16_14',    'W'),
        ('uint16_16',    'W'),
        ('uint16_18',    'W'),
        ('uint16_1a',    'W'),
        ('uint16_1c',    'W'),
        ('uint16_1e',    'W'),
        ('uint8_20',     'B'),
        ('uint8_21',     'B'),
        ('uint8_22',     'B'),
        ('uint8_23',     'B'),
        ('uint8_24',     'B'),
        ('uint8_25',     'B'),
        ('uint8_26',     'B'),
        ('pad27',        'P1'),
    )
