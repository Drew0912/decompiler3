from falcom.ed9.parser.tbl import TableDataEntry


# t_popup_face.tbl
class PopupFaceParam(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',      'W'),
        ('pad02',      'P6'),
        ('nodeName',   'S'),
        ('str10',      'S'),
        ('uint32_18',  'I'),
        ('float32_1c', 'f'),
        ('float32_20', 'f'),
        ('float32_24', 'f'),
        ('float32_28', 'f'),
        ('float32_2c', 'f'),
        ('float32_30', 'f'),
        ('float32_34', 'f'),
        ('float32_38', 'f'),
        ('float32_3c', 'f'),
        ('float32_40', 'f'),
        ('float32_44', 'f'),
        ('float32_48', 'f'),
        ('float32_4c', 'f'),
        ('float32_50', 'f'),
        ('float32_54', 'f'),
        ('float32_58', 'f'),
        ('float32_5c', 'f'),
    )
