from falcom.ed9.parser.tbl import TableDataEntry


# t_graphics_preset.tbl
class GraphicsPresetTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',       'I'),
        ('pad04',    'P4'),
        ('str08',    'S'),
        ('flags',    'S'),
        ('uint8_18', 'B'),
        ('uint8_19', 'B'),
        ('uint8_1a', 'B'),
        ('uint8_1b', 'B'),
        ('uint8_1c', 'B'),
        ('uint8_1d', 'B'),
        ('uint8_1e', 'B'),
        ('uint8_1f', 'B'),
        ('uint8_20', 'B'),
        ('uint8_21', 'B'),
        ('uint8_22', 'B'),
        ('pad23',    'P5'),
    )
