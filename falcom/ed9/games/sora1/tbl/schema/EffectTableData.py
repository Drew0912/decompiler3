from falcom.ed9.parser.tbl import TableDataEntry


# t_effect.tbl
class EffectTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',    'I'),
        ('pad04', 'P4'),
        ('file',  'S'),
        ('flags', 'S'),
    )
