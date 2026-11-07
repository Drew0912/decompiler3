from falcom.ed9.parser.tbl import TableDataEntry


# t_effect.tbl
class EffectTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )
