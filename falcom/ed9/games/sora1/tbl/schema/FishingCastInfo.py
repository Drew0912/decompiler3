from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_fishing.tbl
class FishingCastInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('float32_04', 'f'),
        ('float32_08', 'f'),
    )
