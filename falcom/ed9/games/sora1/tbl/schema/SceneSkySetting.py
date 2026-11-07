from falcom.ed9.parser.tbl import TableDataEntry


# t_scene_setting.tbl
class SceneSkySetting(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('float32_10', 'f'),
        ('float32_14', 'f'),
        ('float32_18', 'f'),
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
    )
