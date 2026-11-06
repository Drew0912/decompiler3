"""sora1's .tbl record classes, the base of sora2's: falcom/ed9/parser/tbl.py reads a section through them. Fields named
by offset have no known meaning yet"""

from falcom.ed9.parser.tbl import RawTableEntry, TableDataEntry    # RawTableEntry: for generated files' star import

# A DESCRIPTOR's kinds, defined in FIELD_KINDS (falcom/ed9/parser/tbl.py); integers are unsigned
#   W   Word: 2-byte integer, printed in hex
#   I   Int: 4-byte integer, printed in decimal
#   L   Long: 4-byte integer, printed in hex
#   Q   Quad: 8-byte integer, printed in decimal
#   X   heX: 8-byte integer, printed in hex
#   f   float: 4 bytes
#   S   String: 8-byte pointer to a NUL-ended string in the data block
#   A2  Array of 2-byte integers: 8-byte pointer into the data block, 4-byte element count
#   A4  Array of 4-byte integers: the same


# t_name.tbl
class NameTableData(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',   'X'),
        ('chrName', 'S'),
        ('model',   'S'),
        ('face',    'S'),
        ('ani',     'S'),
        ('num28',   'Q'),
        ('str30',   'S'),
        ('num38',   'Q'),
        ('str40',   'S'),
        ('num48',   'Q'),
        ('str50',   'S'),
        ('str58',   'S'),
        ('str60',   'S'),
    )


# t_npc_*.tbl
class NPCParam(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',           'W'),
        ('altChrId',        'W'),
        ('int04',           'I'),
        ('str08',           'S'),
        ('arr10',           'A2'),
        ('int1c',           'I'),
        ('arr20',           'A2'),
        ('x',               'f'),
        ('y',               'f'),
        ('z',               'f'),
        ('angle',           'f'),
        ('float3c',         'f'),
        ('float40',         'f'),
        ('int44',           'I'),
        ('float48',         'f'),
        ('float4c',         'f'),
        ('float50',         'f'),
        ('int54',           'I'),
        ('str58',           'S'),
        ('faceFunction',    'S'),
        ('aniFunction',     'S'),
        ('int70',           'I'),
        ('int74',           'I'),
        ('talkFunction',    'S'),
        ('str80',           'S'),
        ('num88',           'Q'),
        ('arr90',           'A2'),
        ('int9c',           'I'),
    )


# t_npc_c0000.tbl only
class NPCParam98(TableDataEntry):
    SECTION = 'NPCParam'
    DESCRIPTOR = (
        ('chrId',       'W'),
        ('altChrId',    'W'),
        ('int04',       'I'),
        ('str08',       'S'),
        ('arr10',       'A2'),
        ('int1c',       'I'),
        ('arr20',       'A2'),
        ('x',           'f'),
        ('y',           'f'),
        ('z',           'f'),
        ('angle',       'f'),
        ('float3c',     'f'),
        ('int40',       'I'),
        ('int44',       'I'),
        ('int48',       'I'),
        ('int4c',       'I'),
        ('str50',       'S'),
        ('str58',       'S'),
        ('aniFunction', 'S'),
        ('num68',       'Q'),
        ('str70',       'S'),
        ('str78',       'S'),
        ('num80',       'Q'),
        ('arr88',       'A2'),
        ('int94',       'I'),
    )


# t_mon_*.tbl
class MonsterSettingParam(TableDataEntry):
    DESCRIPTOR = (
        ('model',           'S'),
        ('id08',            'X'),
        ('arr10',           'A4'),
        ('int1c',           'I'),
        ('str20',           'S'),
        ('num28',           'Q'),
        ('arr30',           'A2'),
        ('int3c',           'I'),
        ('arr40',           'A2'),
        ('int4c',           'I'),
        ('battleArea',      'S'),
        ('hex58',           'L'),
        ('x',               'f'),
        ('y',               'f'),
        ('z',               'f'),
        ('angle',           'f'),
        ('int6c',           'I'),
        ('hex70',           'L'),
        ('int74',           'I'),
        ('str78',           'S'),
        ('moveFunction',    'S'),
        ('str88',           'S'),
        ('num90',           'Q'),
        ('int98',           'I'),
        ('int9c',           'I'),
        ('strA0',           'S'),
    )
