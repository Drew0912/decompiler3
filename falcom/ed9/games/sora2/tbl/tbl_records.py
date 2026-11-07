"""sora2's .tbl record classes: sora1's, plus what differs here (a class of the same name replaces sora1's)"""

from falcom.ed9.games.sora1.tbl.tbl_records import *

# A DESCRIPTOR's kinds, defined in FIELD_KINDS (falcom/ed9/parser/tbl.py); integers are unsigned but for b, w and i
#   b   Byte: 1-byte signed integer, printed in decimal
#   B   Byte: 1-byte integer, printed in decimal
#   w   Word: 2-byte signed integer, printed in decimal
#   W   Word: 2-byte integer, printed in hex
#   H   Half: 2-byte integer, printed in decimal
#   i   Int: 4-byte signed integer, printed in decimal
#   I   Int: 4-byte integer, printed in decimal
#   L   Long: 4-byte integer, printed in hex
#   Q   Quad: 8-byte integer, printed in decimal
#   X   heX: 8-byte integer, printed in hex
#   f   float: 4 bytes
#   S   String: 8-byte pointer to a NUL-ended string in the data block
#   A1  Array of 1-byte integers: 8-byte pointer into the data block, 4-byte element count
#   A2  Array of 2-byte integers: the same
#   A4  Array of 4-byte integers: the same
#   AF  Array of 4-byte floats: the same
#   P1  Padding: 1 zero byte, not a field of a row; P2 to P7 the same


# t_mon_*.tbl: sora1's, up to its last four fields
class MonsterSettingParam(TableDataEntry):
    DESCRIPTOR = MonsterSettingParam.DESCRIPTOR[:-4] + (
        ('arr32_90',     'A4'),
        ('uint32_9c',    'I'),
        ('bgmSet',       'I'),
        ('atBonus',      'I'),
        ('battleScript', 'S'),
    )


# t_mon_a1000.tbl, t_mon_a1005.tbl: no last string
class MonsterSettingParamA8(TableDataEntry):
    SECTION = 'MonsterSettingParam'
    DESCRIPTOR = MonsterSettingParam.DESCRIPTOR[:-1]


# t_break_object.tbl
class BreakObjectTableData(TableDataEntry):
    DESCRIPTOR = (
        ('mapKey',    'S'),
        ('name',      'S'),
        ('statusKey', 'S'),
        ('function',  'S'),
        ('flag',      'W'),
        ('itemGroup', 'W'),
        ('countA',    'W'),
        ('countB',    'W'),
        ('str28',     'S'),
        ('flags',     'S'),
        ('uint64_38', 'Q'),
    )


# t_btlsys.tbl
class BattleLevelTurn(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('uint32_20', 'I'),
        ('uint32_24', 'I'),
    )


class BattleLevelEnemyAdjust(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
    )


# t_chrdata.tbl
class ChrDataParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('float32_04', 'f'),
        ('float32_08', 'f'),
        ('float32_0c', 'f'),
        ('float32_10', 'f'),
        ('float32_14', 'f'),
        ('float32_18', 'f'),
        ('float32_1c', 'f'),
        ('float32_20', 'f'),
        ('float32_24', 'f'),
        ('uint32_28',  'I'),
        ('uint32_2c',  'I'),
        ('float32_30', 'f'),
        ('uint32_34',  'I'),
    )


class PortraitDataParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('float32_18', 'f'),
        ('float32_1c', 'f'),
        ('float32_20', 'f'),
        ('float32_24', 'f'),
        ('float32_28', 'f'),
        ('float32_2c', 'f'),
    )


# t_face_anime.tbl
class LipSyncData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
    )


# t_item.tbl
class ItemTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',           'I'),
        ('pad04',        'P4'),
        ('chrIds',       'A4'),
        ('uint32_14',    'I'),
        ('flags',        'S'),
        ('flags2',       'S'),
        ('category',     'B'),
        ('subcategory',  'B'),
        ('uint16_2a',    'W'),
        ('uint16_2c',    'W'),
        ('uint8_2e',     'B'),
        ('pad2f',        'P1'),
        ('typeCode',     'W'),
        ('pad32',        'P2'),
        ('float32_34',   'f'),
        ('float32_38',   'f'),
        ('effect1Code',  'W'),
        ('pad3e',        'P2'),
        ('effect1Value', 'I'),
        ('uint32_44',    'I'),
        ('uint32_48',    'I'),
        ('effect2Code',  'W'),
        ('pad4e',        'P2'),
        ('effect2Value', 'I'),
        ('uint32_54',    'I'),
        ('uint32_58',    'I'),
        ('effect3Code',  'W'),
        ('pad5e',        'P2'),
        ('effect3Value', 'I'),
        ('uint32_64',    'I'),
        ('uint32_68',    'I'),
        ('effect4Code',  'W'),
        ('pad6e',        'P2'),
        ('effect4Value', 'I'),
        ('uint32_74',    'I'),
        ('uint32_78',    'I'),
        ('effect5Code',  'W'),
        ('pad7e',        'P2'),
        ('effect5Value', 'I'),
        ('uint32_84',    'I'),
        ('uint32_88',    'I'),
        ('float32_8c',   'f'),
        ('float32_90',   'f'),
        ('uint32_94',    'I'),
        ('uint32_98',    'I'),
        ('uint32_9c',    'I'),
        ('uint32_a0',    'I'),
        ('uint32_a4',    'I'),
        ('uint32_a8',    'I'),
        ('uint32_ac',    'I'),
        ('uint32_b0',    'I'),
        ('uint32_b4',    'I'),
        ('uint32_b8',    'I'),
        ('uint32_bc',    'I'),
        ('uint32_c0',    'I'),
        ('uint32_c4',    'I'),
        ('uint32_c8',    'I'),
        ('maxCount',     'I'),
        ('price',        'I'),
        ('padd4',        'P4'),
        ('useFunction',  'S'),
        ('name',         'S'),
        ('description',  'S'),
        ('uint32_f0',    'I'),
        ('uint32_f4',    'I'),
        ('uint32_f8',    'I'),
        ('uint32_fc',    'I'),
    )


# t_mapjump.tbl
class MapJumpChrIcon(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',      'I'),
        ('float32_04', 'f'),
        ('uint32_08',  'I'),
    )


# t_minigame_blackjack.tbl
class BlackJackMessage(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
        ('str18',     'S'),
    )


class BlackJackInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
    )


class BlackJackRollRate(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
        ('uint32_20', 'I'),
        ('uint32_24', 'I'),
        ('uint32_28', 'I'),
        ('uint32_2c', 'I'),
        ('uint32_30', 'I'),
        ('uint32_34', 'I'),
        ('uint32_38', 'I'),
        ('uint32_3c', 'I'),
        ('uint32_40', 'I'),
        ('uint32_44', 'I'),
        ('uint32_48', 'I'),
        ('uint32_4c', 'I'),
        ('uint32_50', 'I'),
        ('uint32_54', 'I'),
        ('uint32_58', 'I'),
        ('uint32_5c', 'I'),
        ('uint32_60', 'I'),
        ('uint32_64', 'I'),
        ('uint32_68', 'I'),
        ('uint32_6c', 'I'),
        ('uint64_70', 'Q'),
        ('uint32_78', 'I'),
        ('uint32_7c', 'I'),
    )


class BlackJackRuleText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )


# t_minigame_fishing.tbl
class FishInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('uint32_04',  'I'),
        ('str08',      'S'),
        ('uint32_10',  'I'),
        ('uint32_14',  'I'),
        ('uint32_18',  'I'),
        ('uint32_1c',  'I'),
        ('uint32_20',  'I'),
        ('uint32_24',  'I'),
        ('uint32_28',  'I'),
        ('uint32_2c',  'I'),
        ('uint32_30',  'I'),
        ('uint32_34',  'I'),
        ('uint32_38',  'I'),
        ('uint32_3c',  'I'),
        ('uint32_40',  'I'),
        ('uint32_44',  'I'),
        ('uint32_48',  'I'),
        ('uint32_4c',  'I'),
        ('uint32_50',  'I'),
        ('uint32_54',  'I'),
        ('uint32_58',  'I'),
        ('uint32_5c',  'I'),
        ('uint32_60',  'I'),
        ('uint32_64',  'I'),
        ('uint32_68',  'I'),
        ('uint32_6c',  'I'),
        ('uint32_70',  'I'),
        ('uint32_74',  'I'),
        ('uint32_78',  'I'),
        ('uint32_7c',  'I'),
        ('uint32_80',  'I'),
        ('uint32_84',  'I'),
        ('float32_88', 'f'),
        ('float32_8c', 'f'),
        ('float32_90', 'f'),
        ('float32_94', 'f'),
        ('float32_98', 'f'),
        ('float32_9c', 'f'),
        ('float32_a0', 'f'),
        ('float32_a4', 'f'),
        ('float32_a8', 'f'),
        ('float32_ac', 'f'),
        ('float32_b0', 'f'),
        ('float32_b4', 'f'),
        ('float32_b8', 'f'),
        ('float32_bc', 'f'),
        ('float32_c0', 'f'),
        ('float32_c4', 'f'),
        ('float32_c8', 'f'),
        ('float32_cc', 'f'),
        ('strd0',      'S'),
        ('uint64_d8',  'Q'),
    )


class FishingConstant(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('float32_04', 'f'),
        ('float32_08', 'f'),
        ('float32_0c', 'f'),
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
        ('float32_48', 'f'),
        ('float32_4c', 'f'),
        ('uint32_50',  'I'),
        ('uint32_54',  'I'),
        ('str58',      'S'),
    )


class FishingBaitInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('uint64_20', 'Q'),
        ('uint64_28', 'Q'),
        ('uint64_30', 'Q'),
        ('uint64_38', 'Q'),
        ('uint64_40', 'Q'),
        ('uint64_48', 'Q'),
        ('uint64_50', 'Q'),
        ('uint64_58', 'Q'),
        ('uint64_60', 'Q'),
        ('uint64_68', 'Q'),
        ('uint32_70', 'I'),
    )


class FishingRodInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('uint32_04',  'I'),
        ('uint32_08',  'I'),
        ('uint32_0c',  'I'),
        ('uint32_10',  'I'),
        ('uint32_14',  'I'),
        ('uint32_18',  'I'),
        ('uint32_1c',  'I'),
        ('uint32_20',  'I'),
        ('uint32_24',  'I'),
        ('uint32_28',  'I'),
        ('uint32_2c',  'I'),
        ('uint32_30',  'I'),
        ('uint32_34',  'I'),
        ('uint32_38',  'I'),
        ('uint32_3c',  'I'),
        ('uint32_40',  'I'),
        ('uint32_44',  'I'),
        ('uint32_48',  'I'),
        ('float32_4c', 'f'),
        ('float32_50', 'f'),
        ('float32_54', 'f'),
        ('float32_58', 'f'),
        ('float32_5c', 'f'),
    )


class OutItemList(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('uint32_20', 'I'),
        ('uint32_24', 'I'),
        ('uint64_28', 'Q'),
        ('uint64_30', 'Q'),
        ('uint64_38', 'Q'),
    )


class FishingSpot(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('str08',     'S'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('arr16_18',  'A2'),
        ('uint32_24', 'I'),
        ('arr16_28',  'A2'),
        ('uint32_34', 'I'),
        ('uint32_38', 'I'),
        ('uint32_3c', 'I'),
        ('uint32_40', 'I'),
        ('uint32_44', 'I'),
        ('uint32_48', 'I'),
        ('uint32_4c', 'I'),
        ('uint32_50', 'I'),
        ('uint32_54', 'I'),
        ('uint32_58', 'I'),
        ('uint32_5c', 'I'),
        ('uint32_60', 'I'),
        ('uint32_64', 'I'),
        ('uint32_68', 'I'),
        ('uint32_6c', 'I'),
        ('uint32_70', 'I'),
        ('uint32_74', 'I'),
        ('uint32_78', 'I'),
        ('uint32_7c', 'I'),
        ('uint32_80', 'I'),
        ('uint32_84', 'I'),
        ('uint32_88', 'I'),
        ('uint32_8c', 'I'),
        ('uint32_90', 'I'),
        ('uint32_94', 'I'),
        ('uint32_98', 'I'),
        ('uint32_9c', 'I'),
        ('uint32_a0', 'I'),
        ('uint32_a4', 'I'),
        ('uint32_a8', 'I'),
        ('uint32_ac', 'I'),
        ('uint32_b0', 'I'),
        ('uint32_b4', 'I'),
    )


# t_minigame_poker.tbl
class PokerMessage(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
        ('str18',     'S'),
    )


class PokerInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
    )


class PokerRollRate(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
        ('uint32_20', 'I'),
        ('uint32_24', 'I'),
        ('uint32_28', 'I'),
        ('uint32_2c', 'I'),
        ('uint32_30', 'I'),
        ('uint32_34', 'I'),
        ('uint32_38', 'I'),
        ('uint32_3c', 'I'),
        ('uint32_40', 'I'),
        ('uint32_44', 'I'),
        ('uint32_48', 'I'),
        ('uint32_4c', 'I'),
        ('uint32_50', 'I'),
        ('uint32_54', 'I'),
        ('uint32_58', 'I'),
        ('uint32_5c', 'I'),
        ('uint32_60', 'I'),
        ('uint32_64', 'I'),
        ('uint32_68', 'I'),
        ('uint32_6c', 'I'),
        ('uint32_70', 'I'),
        ('uint32_74', 'I'),
        ('uint64_78', 'Q'),
    )


class PokerRuleText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )


# t_minigame_roulette.tbl
class RouletteMessage(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )


class RouletteInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
    )


class RouletteBetRate(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('uint64_20', 'Q'),
    )


class RouletteCheat(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
    )


class RouletteBetExplain(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class RouletteRuleText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )


class RouletteNumber(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('float32_04', 'f'),
        ('float32_08', 'f'),
    )


# t_minigame_slot.tbl
class SlotReelPattern(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint16_04', 'W'),
    )


class SlotReelSpeed(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('float32_04', 'f'),
    )


class SlotInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
    )


class SlotRoles(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
    )


class SlotBonus(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
    )


class SlotCheat(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
    )


class SlotEvent(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
    )


class SlotTBoxEvent(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
    )


class SlotBattleEvent(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
    )


class SlotPomInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
    )


class SlotMonsterInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('uint32_20', 'I'),
        ('uint32_24', 'I'),
        ('uint32_28', 'I'),
        ('uint32_2c', 'I'),
    )


class SlotTBoxInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('uint32_20', 'I'),
        ('uint32_24', 'I'),
        ('uint32_28', 'I'),
        ('uint32_2c', 'I'),
        ('uint32_30', 'I'),
    )


# t_notemenu.tbl
class NoteMainPartnerInfo(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )


class NoteMainHistory8(TableDataEntry):
    SECTION = 'NoteMainHistory'
    DESCRIPTOR = (
        ('str00', 'S'),
    )


class NoteFishingCategory(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
    )


class NoteMonsRecordData(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('arr16_10',  'A2'),
        ('uint32_1c', 'I'),
        ('str20',     'S'),
        ('str28',     'S'),
    )


class NoteCookChara(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('arr16_08',  'A2'),
        ('uint32_14', 'I'),
    )


# t_orbment.tbl
class OrbmentSlotParam(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',     'I'),
        ('line',      'b'),
        ('uint8_05',  'B'),
        ('kind',      'B'),
        ('uint8_07',  'B'),
        ('uint16_08', 'W'),
        ('uint16_0a', 'W'),
        ('uint16_0c', 'W'),
        ('uint16_0e', 'W'),
        ('uint16_10', 'W'),
        ('uint16_12', 'W'),
        ('uint16_14', 'W'),
        ('uint16_16', 'W'),
        ('uint16_18', 'W'),
        ('uint16_1a', 'W'),
        ('uint16_1c', 'W'),
        ('uint16_1e', 'W'),
        ('uint16_20', 'W'),
        ('uint16_22', 'W'),
        ('uint16_24', 'W'),
        ('uint16_26', 'W'),
        ('uint16_28', 'W'),
        ('uint16_2a', 'W'),
        ('uint16_2c', 'W'),
        ('uint16_2e', 'W'),
        ('uint16_30', 'W'),
        ('uint16_32', 'W'),
        ('uint16_34', 'W'),
        ('uint16_36', 'W'),
        ('uint16_38', 'W'),
        ('uint16_3a', 'W'),
        ('uint16_3c', 'W'),
        ('pad3e',     'P2'),
    )


# t_quest.tbl
class QuestRankBefore(TableDataEntry):
    DESCRIPTOR = (
        ('rank',      'I'),
        ('threshold', 'I'),
        ('name',      'S'),
    )


class QuestText38(TableDataEntry):
    SECTION = 'QuestText'
    DESCRIPTOR = (
        ('questId',   'W'),
        ('stage',     'W'),
        ('pad04',     'P4'),
        ('text',      'S'),
        ('flagsSet',  'A2'),
        ('uint32_1c', 'I'),
        ('arr16_20',  'A2'),
        ('uint32_2c', 'I'),
        ('str30',     'S'),
    )


class NaviText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('text',       'S'),
        ('altText',    'S'),
        ('flagsSet',   'A2'),
        ('uint32_24',  'I'),
        ('flagsClear', 'A2'),
        ('uint32_34',  'I'),
    )


# t_shop.tbl
class MedalItem(TableDataEntry):
    DESCRIPTOR = (
        ('itemId', 'I'),
        ('price',  'I'),
    )


class CharaArrange(TableDataEntry):
    DESCRIPTOR = (
        ('uint16_00',   'W'),
        ('pad02',       'P2'),
        ('uint32_04',   'I'),
        ('aniFunction', 'S'),
        ('str10',       'S'),
        ('str18',       'S'),
        ('x',           'f'),
        ('y',           'f'),
        ('z',           'f'),
        ('angle',       'f'),
        ('flags',       'S'),
        ('float32_38',  'f'),
        ('float32_3c',  'f'),
        ('float32_40',  'f'),
        ('pad44',       'P4'),
    )


# t_skill.tbl
class SkillGetParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint16_08', 'W'),
    )


# t_status.tbl
class StatusParam(TableDataEntry):
    DESCRIPTOR = (
        ('key',         'S'),
        ('flags',       'S'),
        ('chrClass',    'B'),
        ('uint8_11',    'B'),
        ('pad12',       'P6'),
        ('model',       'S'),
        ('face',        'S'),
        ('str28',       'S'),
        ('str30',       'S'),
        ('aiScript',    'S'),
        ('str40',       'S'),
        ('chrId',       'W'),
        ('pad4a',       'P2'),
        ('float32_4c',  'f'),
        ('float32_50',  'f'),
        ('float32_54',  'f'),
        ('float32_58',  'f'),
        ('float32_5c',  'f'),
        ('float32_60',  'f'),
        ('float32_64',  'f'),
        ('scaleMin',    'f'),
        ('scaleMax',    'f'),
        ('float32_70',  'f'),
        ('float32_74',  'f'),
        ('float32_78',  'f'),
        ('float32_7c',  'f'),
        ('float32_80',  'f'),
        ('float32_84',  'f'),
        ('float32_88',  'f'),
        ('float32_8c',  'f'),
        ('float32_90',  'f'),
        ('float32_94',  'f'),
        ('flags2',      'S'),
        ('uint32_a0',   'I'),
        ('pada4',       'P4'),
        ('uint32_a8',   'I'),
        ('float32_ac',  'f'),
        ('float32_b0',  'f'),
        ('float32_b4',  'f'),
        ('float32_b8',  'f'),
        ('float32_bc',  'f'),
        ('float32_c0',  'f'),
        ('float32_c4',  'f'),
        ('float32_c8',  'f'),
        ('float32_cc',  'f'),
        ('uint32_d0',   'I'),
        ('float32_d4',  'f'),
        ('float32_d8',  'f'),
        ('float32_dc',  'f'),
        ('uint8_e0',    'B'),
        ('pade1',       'P3'),
        ('uint32_e4',   'I'),
        ('float32_e8',  'f'),
        ('uint32_ec',   'I'),
        ('float32_f0',  'f'),
        ('uint32_f4',   'I'),
        ('uint32_f8',   'I'),
        ('uint32_fc',   'I'),
        ('uint32_100',  'I'),
        ('float32_104', 'f'),
        ('uint32_108',  'I'),
        ('float32_10c', 'f'),
        ('uint32_110',  'I'),
        ('float32_114', 'f'),
        ('uint32_118',  'I'),
        ('float32_11c', 'f'),
        ('uint32_120',  'I'),
        ('float32_124', 'f'),
        ('uint32_128',  'I'),
        ('float32_12c', 'f'),
        ('uint32_130',  'I'),
        ('float32_134', 'f'),
        ('uint32_138',  'I'),
        ('uint32_13c',  'I'),
        ('uint32_140',  'I'),
        ('uint32_144',  'I'),
        ('uint32_148',  'I'),
        ('avoid',       'I'),
        ('uint32_150',  'I'),
        ('uint32_154',  'I'),
        ('uint8_158',   'B'),
        ('uint8_159',   'B'),
        ('uint8_15a',   'B'),
        ('uint8_15b',   'B'),
        ('uint8_15c',   'B'),
        ('uint8_15d',   'B'),
        ('uint8_15e',   'B'),
        ('uint8_15f',   'B'),
        ('uint8_160',   'B'),
        ('uint8_161',   'B'),
        ('uint8_162',   'B'),
        ('uint8_163',   'B'),
        ('uint8_164',   'B'),
        ('pad165',      'P1'),
        ('int16_166',   'w'),
        ('int16_168',   'w'),
        ('int16_16a',   'w'),
        ('int16_16c',   'w'),
        ('int16_16e',   'w'),
        ('int16_170',   'w'),
        ('int16_172',   'w'),
        ('uint8_174',   'B'),
        ('uint8_175',   'B'),
        ('uint8_176',   'B'),
        ('uint8_177',   'B'),
        ('uint8_178',   'B'),
        ('uint8_179',   'B'),
        ('uint8_17a',   'B'),
        ('uint8_17b',   'B'),
        ('uint32_17c',  'I'),
        ('uint32_180',  'I'),
        ('drop1Item',   'I'),
        ('drop1CountA', 'B'),
        ('drop1CountB', 'B'),
        ('drop1Chance', 'B'),
        ('pad18b',      'P1'),
        ('drop2Item',   'I'),
        ('drop2CountA', 'B'),
        ('drop2CountB', 'B'),
        ('drop2Chance', 'B'),
        ('pad193',      'P1'),
        ('pad194',      'P4'),
        ('name',        'S'),
        ('comment',     'S'),
    )


# t_talk.tbl
class TalkTableData(TableDataEntry):
    DESCRIPTOR = (
        ('scriptArgument', 'I'),
        ('version',        'I'),
        ('mapKey',         'S'),
        ('chrId',          'W'),
        ('pad12',          'P6'),
        ('flagsSet',       'A2'),
        ('uint32_24',      'I'),
        ('flagsClear',     'A2'),
        ('uint32_34',      'I'),
        ('flagsOnChange',  'A2'),
        ('uint32_44',      'I'),
        ('arr16_48',       'A2'),
        ('uint32_54',      'I'),
    )


# t_tbox.tbl
class TBoxParam(TableDataEntry):
    DESCRIPTOR = (
        ('mapKey',      'S'),
        ('name',        'S'),
        ('uint64_10',   'Q'),
        ('flags',       'S'),
        ('function',    'S'),
        ('flag1',       'W'),
        ('flag2',       'W'),
        ('pad2c',       'P4'),
        ('arr16_30',    'A2'),
        ('uint32_3c',   'I'),
        ('uint64_40',   'Q'),
        ('arr16_48',    'A2'),
        ('uint32_54',   'I'),
        ('conditionsA', 'A2'),
        ('uint32_64',   'I'),
        ('conditionsB', 'A2'),
        ('uint32_74',   'I'),
    )


# t_viewer.tbl
class ViewerMainList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )


class ViewerSystemList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class ViewerMapList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class ViewerCharaSelectList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )


class ViewerCharaEquipList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )


class ViewerShotList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class ViewerMapData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('arr16_18',   'A2'),
        ('uint32_24',  'I'),
        ('str28',      'S'),
        ('uint32_30',  'I'),
        ('uint32_34',  'I'),
        ('str38',      'S'),
        ('float32_40', 'f'),
        ('float32_44', 'f'),
        ('float32_48', 'f'),
        ('uint32_4c',  'I'),
    )


class ViewerEnvList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class ViewerBGMList(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )


class ViewerCharaList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('str18',      'S'),
        ('uint32_20',  'I'),
        ('uint32_24',  'I'),
        ('str28',      'S'),
        ('str30',      'S'),
        ('float32_38', 'f'),
        ('float32_3c', 'f'),
    )


class ViewerCostumeList(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('str18',     'S'),
    )


class ViewerAttachList(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint64_18', 'Q'),
    )


class ViewerHairList(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )


class ViewerWeaponList(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )


class ViewerFaceList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
        ('uint64_20', 'Q'),
        ('str28',     'S'),
    )


class ViewerMouseList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )


class ViewerCheekList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )


class ViewerEyeLineList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )


class ViewerNeckDirList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('float32_10', 'f'),
        ('float32_14', 'f'),
    )


class ViewerMotionList(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
        ('str20',     'S'),
    )
