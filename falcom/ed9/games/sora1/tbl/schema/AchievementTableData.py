from falcom.ed9.parser.tbl import TableDataEntry


# t_achievement.tbl
class AchievementTableData(TableDataEntry):
    DESCRIPTOR = (
        ('categoryId',  'B'),   # an AchievementCategoryData id; the list starts a new group where it changes
        ('pad01',       'P3'),
        ('saveIndex',   'I'),
        ('workIndex',   'I'),   # a global work index; a lookup key, not unique
        ('target',      'i'),
        ('cap',         'i'),
        ('pad14',       'P4'),
        ('arr32_18',    'A4'),
        ('flag',        'W'),   # scenario flag that must be set; 0: none
        ('uint8_26',    'B'),
        ('pad27',       'P1'),
        ('itemId',      'W'),   # a reward, by its use
        ('altItemId',   'W'),   # with altAmount, can replace itemId and amount; 0: none
        ('amount',      'I'),   # the count for itemId, by its use
        ('altAmount',   'I'),
        ('item2Id',     'W'),
        ('pad36',       'P2'),
        ('amount2',     'I'),
        ('pad3c',       'P4'),
        # flags, a bit per letter:
        #   C 0x1: a locked row with C doesn't stop the "all achievements unlocked" test; when that test holds, the game
        #     apparently unlocks achievement 2
        #   2 0x4: only its own flag unlocks it; while scenario flag 405 is set, rows without 2 count as unlocked anyway
        #     (405: apparently a carried-over New Game+ save)
        #   H 0x2: the row is neither counted nor listed, nor is a later row with the same workIndex
        ('flags',       'S'),
        ('name',        'S'),
        ('description', 'S'),
        ('str58',       'S'),
    )
