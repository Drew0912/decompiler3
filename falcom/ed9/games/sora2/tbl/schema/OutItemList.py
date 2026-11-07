from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_fishing.tbl
class OutItemList(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('uint32_20', 'I'),
        ('uint32_24', 'I'),
        ('uint64_28', 'Q'),
        ('uint64_30', 'Q'),
        ('uint64_38', 'Q'),
    )
