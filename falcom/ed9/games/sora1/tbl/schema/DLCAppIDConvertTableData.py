from falcom.ed9.parser.tbl import TableDataEntry


# t_dlc_appid_convert.tbl
class DLCAppIDConvertTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'I'),
        ('appNumber', 'I'),
    )
