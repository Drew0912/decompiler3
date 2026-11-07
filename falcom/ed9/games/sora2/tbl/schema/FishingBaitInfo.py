from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_fishing.tbl
class FishingBaitInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('uint64_20', 'Q'),
        ('uint64_28', 'Q'),
        ('uint64_30', 'Q'),
        ('uint64_38', 'Q'),
        ('uint64_40', 'Q'),
        ('uint64_48', 'Q'),
        ('uint64_50', 'Q'),
        ('uint64_58', 'Q'),
        ('uint64_60', 'Q'),
        ('uint64_68', 'Q'),
        ('uint32_70', 'I'),
    )
