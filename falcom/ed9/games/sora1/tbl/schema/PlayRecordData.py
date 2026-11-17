from falcom.ed9.parser.tbl import TableDataEntry


# t_achievement.tbl
class PlayRecordData(TableDataEntry):
    DESCRIPTOR = (
        ('trophy', 'B'),   # shown by the trophy UI element: 0 to 3, 3 only on the all-achievements record
        ('pad01',  'P7'),
        # flags, 1 when it holds H, else 0 (not a mask):
        #   H: text and text2 show the text of the key TXT_CAMP_ACHIEVEMENT_NODISP_TEXT while the record's
        #     scenario flag (8000 + row; from row 100 on it counts as clear) is clear, unless scenario flag 404
        #     is set
        ('flags',  'S'),
        ('text',   'S'),
        ('text2',  'S'),
        ('str20',  'S'),   # the goal's wording, by its values; nothing found reading it
    )
