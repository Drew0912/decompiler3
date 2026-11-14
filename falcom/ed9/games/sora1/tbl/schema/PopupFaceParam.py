from falcom.ed9.parser.tbl import TableDataEntry


# t_popup_face.tbl
class PopupFaceParam(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',      'W'),   # 0xFFFF: the default row
        ('pad02',      'P6'),
        ('nodeName',   'S'),
        ('str10',      'S'),   # 'wait' when empty; looked up by name in the actor's clips (a motion name, by a reading)
        ('uint32_18',  'I'),
        # the popup's mode (1 to 6, set by the code showing it) picks the fields: float32_1c..float32_24 for
        # modes 1 and 2, float32_30..float32_38 for 3 to 6; float32_44, float32_48 stand in for the angles
        # when the actor's flag isn't 0 (see each), but no store found sets it to anything but 0
        ('float32_1c', 'f'),   # subtracted from the 2nd component of a negated vector built from the nodeName node
        ('float32_20', 'f'),   # degrees, mode 1
        ('float32_24', 'f'),   # degrees, mode 2
        ('float32_28', 'f'),
        ('float32_2c', 'f'),
        ('float32_30', 'f'),   # as float32_1c
        ('float32_34', 'f'),   # degrees, modes 3, 5
        ('float32_38', 'f'),   # degrees, modes 4, 6
        ('float32_3c', 'f'),
        ('float32_40', 'f'),
        ('float32_44', 'f'),   # degrees, modes 1, 3, 5 when the flag is 1
        ('float32_48', 'f'),   # degrees, mode 2 when the flag is 1, modes 4, 6 when it isn't 0
        ('float32_4c', 'f'),
        ('float32_50', 'f'),
        ('float32_54', 'f'),
        ('float32_58', 'f'),
        ('float32_5c', 'f'),
    )
