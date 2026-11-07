from falcom.ed9.parser.tbl import TableDataEntry


# t_place.tbl
class PlaceTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'I'),
        ('pad04',      'P4'),
        ('mapKey',     'S'),
        ('subMapKey',  'S'),
        ('str18',      'S'),
        ('x',          'f'),
        ('y',          'f'),
        ('z',          'f'),
        ('uint32_2c',  'I'),
        ('flagsSet',   'A2'),
        ('uint32_3c',  'I'),
        ('flagsClear', 'A2'),
        ('float32_4c', 'f'),
        ('uint32_50',  'I'),
        ('uint32_54',  'I'),
        ('flags',      'S'),
        ('name',       'S'),
        ('str68',      'S'),
        ('float32_70', 'f'),
        ('float32_74', 'f'),
        ('arrf32_78',  'AF'),
        ('float32_84', 'f'),
        ('float32_88', 'f'),
        ('float32_8c', 'f'),
        ('uint32_90',  'I'),
        ('uint32_94',  'I'),
        ('secondId',   'I'),
        ('float32_9c', 'f'),
        ('float32_a0', 'f'),
        ('float32_a4', 'f'),
    )
