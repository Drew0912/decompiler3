from falcom.ed9.parser.tbl import TableDataEntry


# t_minigame_slot.tbl
class SlotRoles(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'W'),
        ('icon0',     'W'),  # iconN: 1 to 6 picks an icon cell; 0 or above 6 the default cell
        ('icon1',     'W'),
        ('icon2',     'W'),
        ('uint32_08', 'I'),
    )
