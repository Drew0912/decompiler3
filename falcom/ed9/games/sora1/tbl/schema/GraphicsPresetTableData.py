from falcom.ed9.parser.tbl import TableDataEntry


# t_graphics_preset.tbl
class GraphicsPresetTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('uint64_20', 'Q'),
    )
