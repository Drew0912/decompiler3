from falcom.ed9.parser.tbl import TableDataEntry


# t_place.tbl
class PlaceTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'I'),
        ('pad04',      'P4'),
        ('mapKey',     'S'),
        ('subMapKey',  'S'),
        ('str18',      'S'),
        ('x',          'f'),   # x, y, z: a position, by its use
        ('y',          'f'),
        ('z',          'f'),
        ('uint32_2c',  'I'),
        ('flagsSet',   'A2'),  # scenario flags that must all be set
        ('uint32_3c',  'I'),
        ('flagsClear', 'A2'),  # scenario flags none of which may be set
        ('float32_4c', 'f'),
        ('uint32_50',  'I'),
        ('uint32_54',  'I'),
        # flags, a bit per letter:
        #   A 0x1: sets scenario flag 4 while it is the current place; a place without A clears it
        #   M 0x4: when str18 equals the map's name, the place gets a "map object" (what it is for: not known)
        #   T 0x8, K 0x80: the script function OnChangePlace (script system) plays general voice 25 when the place
        #     left has T and the place entered has K
        #   R 0x20: a lookup of a place by secondId returns mapKey only for a row with R (else an empty string)
        #   D 0x2, Z 0x10, C 0x40, N 0x100, W 0x200, L 0x400, P 0x800: read by code, purpose not known
        #   H 0x1000, E 0x2000: nothing found reading it
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
