from falcom.ed9.parser.tbl import TableDataEntry


# t_bgmset.tbl
class BattleBGM(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'I'),
        ('pad04',      'P4'),
        ('flagsSet',   'A2'),  # scenario flags that must all be set
        ('uint32_14',  'I'),
        ('flagsClear', 'A2'),  # scenario flags none of which may be set
        ('int32_24',   'i'),
        ('bgmId1',     'I'),   # 0: none; one of bgmId1..3 is picked by the caller
        ('bgmId2',     'I'),   # 0: none
        ('bgmId3',     'I'),   # 0: none
        ('pad34',      'P4'),
    )
