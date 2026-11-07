from falcom.ed9.parser.tbl import TableDataEntry


# t_bgmset.tbl
class BattleBGM(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'I'),
        ('pad04',      'P4'),
        ('flagsSet',   'A2'),
        ('uint32_14',  'I'),
        ('flagsClear', 'A2'),
        ('int32_24',   'i'),
        ('bgmId1',     'I'),
        ('bgmId2',     'I'),
        ('bgmId3',     'I'),
        ('pad34',      'P4'),
    )
