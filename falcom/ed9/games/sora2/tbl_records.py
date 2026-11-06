"""sora2's .tbl record classes: sora1's, plus what differs here (a class of the same name replaces sora1's)"""

from falcom.ed9.games.sora1.tbl_records import *

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


# t_mon_*.tbl: sora1's, up to its last four fields
class MonsterSettingParam(TableDataEntry):
    DESCRIPTOR = MonsterSettingParam.DESCRIPTOR[:-4] + (
        ('arr90',   'A4'),
        ('int9c',   'I'),
        ('intA0',   'I'),
        ('intA4',   'I'),
        ('strA8',   'S'),
    )


# t_mon_a1000.tbl, t_mon_a1005.tbl: no last string
class MonsterSettingParamA8(TableDataEntry):
    SECTION = 'MonsterSettingParam'
    DESCRIPTOR = MonsterSettingParam.DESCRIPTOR[:-1]
