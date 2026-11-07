from falcom.ed9.parser.tbl import TableDataEntry


# t_scene_setting.tbl
class SceneCommonSetting(TableDataEntry):
    DESCRIPTOR = (
        ('float32_00', 'f'),
        ('float32_04', 'f'),
        ('float32_08', 'f'),
        ('float32_0c', 'f'),
        ('float32_10', 'f'),
        ('float32_14', 'f'),
        ('float32_18', 'f'),
    )
