from falcom.ed9.parser.tbl import TableDataEntry


# t_effect.tbl
class EffectTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',    'I'),
        ('pad04', 'P4'),
        ('file',  'S'),
        # flags, 1 when it holds E, else 0 (not a mask):
        #   E: nothing found reading it
        ('flags', 'S'),
    )
