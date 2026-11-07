"""sora1's .tbl record classes, the base of sora2's: falcom/ed9/parser/tbl.py reads a section through them. Fields named
by offset have no known meaning yet"""

from falcom.ed9.parser.tbl import TableDataEntry
from falcom.ed9.parser.tbl import RawSection, RawTableEntry, create_tbl    # for generated scripts' star import

# A DESCRIPTOR's kinds, defined in FIELD_KINDS (falcom/ed9/parser/tbl.py); integers are unsigned
#   B   Byte: 1-byte integer, printed in decimal
#   W   Word: 2-byte integer, printed in hex
#   I   Int: 4-byte integer, printed in decimal
#   L   Long: 4-byte integer, printed in hex
#   Q   Quad: 8-byte integer, printed in decimal
#   X   heX: 8-byte integer, printed in hex
#   f   float: 4 bytes
#   S   String: 8-byte pointer to a NUL-ended string in the data block
#   A1  Array of 1-byte integers: 8-byte pointer into the data block, 4-byte element count
#   A2  Array of 2-byte integers: the same
#   A4  Array of 4-byte integers: the same
#   P2  Padding: 2 zero bytes, not a field of a row; P4, P6 and P7 the same


# t_name.tbl
class NameTableData(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',            'W'),
        ('pad02',            'P6'),
        ('chrName',          'S'),
        ('model',            'S'),
        ('face',             'S'),
        ('ani',              'S'),
        ('uint32_28',        'I'),
        ('pad2c',            'P4'),
        ('flags',            'S'),
        ('saveIndex',        'B'),
        ('pad39',            'P7'),
        ('statusKey',        'S'),
        ('scenarioFlag',     'W'),
        ('pad4a',            'P6'),
        ('flaggedStatusKey', 'S'),
        ('str58',            'S'),
        ('str60',            'S'),
    )


# t_npc_*.tbl
class NPCParam(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',        'W'),
        ('altChrId',     'W'),
        ('uint32_04',    'I'),
        ('model',        'S'),
        ('arr16_10',     'A2'),
        ('uint32_1c',    'I'),
        ('arr16_20',     'A2'),
        ('x',            'f'),
        ('y',            'f'),
        ('z',            'f'),
        ('angle',        'f'),
        ('float32_3c',   'f'),
        ('float32_40',   'f'),
        ('lookPoint',    'W'),
        ('pad46',        'P2'),
        ('float32_48',   'f'),
        ('float32_4c',   'f'),
        ('float32_50',   'f'),
        ('uint32_54',    'I'),
        ('flags',        'S'),
        ('initFunction', 'S'),
        ('aniFunction',  'S'),
        ('uint32_70',    'I'),
        ('uint32_74',    'I'),
        ('talkFunction', 'S'),
        ('str80',        'S'),
        ('uint64_88',    'Q'),
        ('arr16_90',     'A2'),
        ('uint32_9c',    'I'),
    )


# t_npc_c0000.tbl only
class NPCParam98(TableDataEntry):
    SECTION = 'NPCParam'
    DESCRIPTOR = (
        ('chrId',       'W'),
        ('altChrId',    'W'),
        ('uint32_04',   'I'),
        ('model',       'S'),
        ('arr16_10',    'A2'),
        ('uint32_1c',   'I'),
        ('arr16_20',    'A2'),
        ('x',           'f'),
        ('y',           'f'),
        ('z',           'f'),
        ('angle',       'f'),
        ('float32_3c',  'f'),
        ('uint32_40',   'I'),
        ('lookPoint',   'W'),
        ('pad46',       'P2'),
        ('uint32_48',   'I'),
        ('uint32_4c',   'I'),
        ('str50',       'S'),
        ('str58',       'S'),
        ('aniFunction', 'S'),
        ('uint64_68',   'Q'),
        ('str70',       'S'),
        ('str78',       'S'),
        ('uint64_80',   'Q'),
        ('arr16_88',    'A2'),
        ('uint32_94',   'I'),
    )


# t_mon_*.tbl
class MonsterSettingParam(TableDataEntry):
    DESCRIPTOR = (
        ('model',        'S'),
        ('chrId',        'W'),
        ('pad0a',        'P6'),
        ('arr32_10',     'A4'),
        ('uint32_1c',    'I'),
        ('flags',        'S'),
        ('uint16_28',    'W'),
        ('pad2a',        'P6'),
        ('arr16_30',     'A2'),
        ('uint32_3c',    'I'),
        ('arr16_40',     'A2'),
        ('uint32_4c',    'I'),
        ('battleArea',   'S'),
        ('uint8_58',     'B'),
        ('uint8_59',     'B'),
        ('uint8_5a',     'B'),
        ('uint8_5b',     'B'),
        ('x',            'f'),
        ('y',            'f'),
        ('z',            'f'),
        ('angle',        'f'),
        ('uint32_6c',    'I'),
        ('uint32_70',    'L'),
        ('uint32_74',    'I'),
        ('initFunction', 'S'),
        ('moveFunction', 'S'),
        ('str88',        'S'),
        ('uint64_90',    'Q'),
        ('uint32_98',    'I'),
        ('uint32_9c',    'I'),
        ('stra0',        'S'),
    )


# t_achievement.tbl
class AchievementTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint64_10', 'Q'),
        ('arr32_18',  'A4'),
        ('uint32_24', 'I'),
        ('uint32_28', 'I'),
        ('uint32_2c', 'I'),
        ('uint32_30', 'I'),
        ('uint32_34', 'I'),
        ('uint64_38', 'Q'),
        ('str40',     'S'),
        ('str48',     'S'),
        ('str50',     'S'),
        ('str58',     'S'),
    )


class AchievementCategoryData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class PlayRecordData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
        ('str20',     'S'),
    )


# t_active_voice.tbl
class ActiveVoiceTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('arr16_08',  'A2'),
        ('uint32_14', 'I'),
        ('str18',     'S'),
        ('uint64_20', 'Q'),
        ('str28',     'S'),
        ('arr16_30',  'A2'),
        ('uint32_3c', 'I'),
        ('arr16_40',  'A2'),
        ('uint32_4c', 'I'),
        ('arr16_50',  'A2'),
        ('uint32_5c', 'I'),
        ('arr32_60',  'A4'),
        ('uint32_6c', 'I'),
        ('str70',     'S'),
        ('uint32_78', 'I'),
        ('uint32_7c', 'I'),
    )


# t_ani_param.tbl
class AniParam(TableDataEntry):
    DESCRIPTOR = (
        ('str00',      'S'),
        ('uint32_08',  'I'),
        ('float32_0c', 'f'),
        ('float32_10', 'f'),
        ('float32_14', 'f'),
        ('float32_18', 'f'),
        ('float32_1c', 'f'),
        ('float32_20', 'f'),
        ('uint32_24',  'I'),
    )


# t_bgm.tbl
class BGMTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('float32_10', 'f'),
        ('uint32_14',  'I'),
    )


# t_bgmset.tbl
class MapBGM(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('arr16_08',   'A2'),
        ('uint32_14',  'I'),
        ('arr16_18',   'A2'),
        ('uint32_24',  'I'),
        ('float32_28', 'f'),
        ('uint32_2c',  'I'),
    )


class BattleBGM(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('arr16_08',  'A2'),
        ('uint32_14', 'I'),
        ('arr16_18',  'A2'),
        ('uint32_24', 'I'),
        ('uint32_28', 'I'),
        ('uint32_2c', 'I'),
        ('uint64_30', 'Q'),
    )


# t_books.tbl
class BooksTitle(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
    )


class BooksText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )


class BooksCategory(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )


# t_break_object.tbl
class BreakObjectTableData(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
        ('uint32_20', 'I'),
        ('uint32_24', 'I'),
        ('str28',     'S'),
        ('str30',     'S'),
    )


class WeedingTableData(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
    )


# t_btl_voice.tbl
class BTLVoiceTable(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('arr16_10',  'A2'),
        ('uint32_1c', 'I'),
        ('arr16_20',  'A2'),
        ('uint32_2c', 'I'),
        ('arr32_30',  'A4'),
        ('uint32_3c', 'I'),
        ('str40',     'S'),
        ('arr8_48',   'A1'),
        ('uint32_54', 'I'),
    )


# t_btlsys.tbl
class ATBonusParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('str20',     'S'),
    )


class ATBonusSet(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
    )


class BattleLevelField(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('uint32_04',  'I'),
        ('uint32_08',  'I'),
        ('float32_0c', 'f'),
    )


class BattleLevelTurn(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
    )


class BattleEnemyLevelStatusAdjust(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
    )


class BattleEnemyDamageAdjust(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
    )


class BattleEnemyLevelAdjust(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
    )


class BattleSCraftDamageRatio(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
    )


class TacticalBonus(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
    )


# t_chapter.tbl
class ChapterParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('str10',     'S'),
        ('str18',     'S'),
        ('str20',     'S'),
        ('str28',     'S'),
        ('str30',     'S'),
        ('uint64_38', 'Q'),
        ('arr32_40',  'A4'),
        ('uint32_4c', 'I'),
        ('str50',     'S'),
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
        ('str30',      'S'),
        ('float32_38', 'f'),
        ('uint32_3c',  'I'),
    )


class TalkChrData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
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
    )


# t_collision_info.tbl
class CollisionFootStepInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('arr32_08',  'A4'),
        ('uint32_14', 'I'),
        ('arr32_18',  'A4'),
        ('uint32_24', 'I'),
    )


# t_condition_info.tbl
class ConditionInfoTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
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
        ('float32_3c', 'f'),
        ('uint64_40',  'Q'),
        ('uint64_48',  'Q'),
        ('str50',      'S'),
    )


class ConditionTypeParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
    )


class OverDriveEffect(TableDataEntry):
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
        ('str30',     'S'),
        ('str38',     'S'),
        ('str40',     'S'),
        ('str48',     'S'),
        ('str50',     'S'),
        ('str58',     'S'),
        ('str60',     'S'),
    )


# t_costume.tbl
class CostumeParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('uint64_18', 'Q'),
        ('str20',     'S'),
        ('str28',     'S'),
        ('str30',     'S'),
    )


class CostumeAttachOffset(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('uint32_10',  'I'),
        ('float32_14', 'f'),
        ('float32_18', 'f'),
        ('uint32_1c',  'I'),
        ('uint64_20',  'Q'),
        ('float32_28', 'f'),
        ('float32_2c', 'f'),
        ('float32_30', 'f'),
        ('uint32_34',  'I'),
    )


# t_dlc.tbl
class DLCTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('arr32_08',  'A4'),
        ('uint32_14', 'I'),
        ('arr32_18',  'A4'),
        ('uint32_24', 'I'),
        ('str28',     'S'),
        ('str30',     'S'),
        ('str38',     'S'),
    )


# t_effect.tbl
class EffectTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )


# t_eventbox.tbl
class EventBoxTableData(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('arr16_18',  'A2'),
        ('uint32_24', 'I'),
        ('arr16_28',  'A2'),
        ('uint32_34', 'I'),
    )


# t_evtable.tbl
class EventGroupData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class EventSubGroupData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class EventTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('uint64_18', 'Q'),
        ('str20',     'S'),
        ('str28',     'S'),
        ('uint64_30', 'Q'),
        ('str38',     'S'),
        ('uint32_40', 'I'),
        ('uint32_44', 'I'),
        ('str48',     'S'),
        ('arr16_50',  'A2'),
        ('uint32_5c', 'I'),
        ('arr16_60',  'A2'),
        ('uint32_6c', 'I'),
        ('str70',     'S'),
        ('uint64_78', 'Q'),
    )


# t_face_anime.tbl
class FaceAnimeData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )


class EyePresetData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint16_04', 'W'),
    )


class EyeScaleData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('float32_04', 'f'),
    )


class MouthPatternMap(TableDataEntry):
    DESCRIPTOR = (
        ('uint16_00', 'W'),
    )


class EyeAttachData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('arr16_08',  'A2'),
        ('uint32_14', 'I'),
        ('str18',     'S'),
    )


class EyeModifyAttachData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('arr16_08',  'A2'),
        ('uint32_14', 'I'),
        ('str18',     'S'),
    )


class EyeDirPatternNameData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class EyeLidsPatternNameData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class EyeBrowsPatternNameData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class EyeModifyPatternNameData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class MouthPatternNameData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class EyeBallSizePatternNameData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class FaceTexturePatternNameData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


# t_field_item.tbl
class FieldItemTableData(TableDataEntry):
    DESCRIPTOR = (
        ('str00',      'S'),
        ('float32_08', 'f'),
        ('float32_0c', 'f'),
        ('float32_10', 'f'),
        ('uint32_14',  'I'),
        ('uint32_18',  'I'),
        ('uint32_1c',  'I'),
    )


# t_graphics_preset.tbl
class GraphicsPresetTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('uint64_20', 'Q'),
    )


# t_help.tbl
class HelpTitle(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )


class HelpPage(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
    )


class HelpIconList(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('uint32_04',  'I'),
        ('str08',      'S'),
        ('float32_10', 'f'),
        ('uint32_14',  'I'),
        ('str18',      'S'),
        ('float32_20', 'f'),
        ('uint32_24',  'I'),
        ('str28',      'S'),
        ('str30',      'S'),
    )


class HelpController(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class HelpOverlayIcon(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('float32_10', 'f'),
        ('float32_14', 'f'),
        ('uint32_18',  'I'),
        ('float32_1c', 'f'),
        ('uint64_20',  'Q'),
    )


class RealTimeHelpTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('uint32_04',  'I'),
        ('str08',      'S'),
        ('float32_10', 'f'),
        ('uint32_14',  'I'),
    )


# t_item.tbl
class ItemTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('uint32_04',  'I'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('uint32_18',  'I'),
        ('uint32_1c',  'I'),
        ('uint32_20',  'I'),
        ('float32_24', 'f'),
        ('float32_28', 'f'),
        ('uint32_2c',  'I'),
        ('uint32_30',  'I'),
        ('uint32_34',  'I'),
        ('uint32_38',  'I'),
        ('uint32_3c',  'I'),
        ('uint32_40',  'I'),
        ('uint32_44',  'I'),
        ('uint32_48',  'I'),
        ('uint32_4c',  'I'),
        ('uint64_50',  'Q'),
        ('uint32_58',  'I'),
        ('uint32_5c',  'I'),
        ('uint32_60',  'I'),
        ('uint32_64',  'I'),
        ('uint32_68',  'I'),
        ('uint32_6c',  'I'),
        ('uint32_70',  'I'),
        ('uint32_74',  'I'),
        ('uint32_78',  'I'),
        ('float32_7c', 'f'),
        ('uint32_80',  'I'),
        ('uint32_84',  'I'),
        ('uint32_88',  'I'),
        ('uint32_8c',  'I'),
        ('uint32_90',  'I'),
        ('uint32_94',  'I'),
        ('uint64_98',  'Q'),
        ('uint32_a0',  'I'),
        ('uint32_a4',  'I'),
        ('uint32_a8',  'I'),
        ('uint32_ac',  'I'),
        ('uint32_b0',  'I'),
        ('uint32_b4',  'I'),
        ('uint32_b8',  'I'),
        ('uint32_bc',  'I'),
        ('strc0',      'S'),
        ('strc8',      'S'),
        ('strd0',      'S'),
        ('uint32_d8',  'I'),
        ('uint32_dc',  'I'),
        ('uint32_e0',  'I'),
        ('uint32_e4',  'I'),
    )


class ItemKindParam2(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class ItemTabType(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
    )


class ItemShopTabType(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
    )


# t_itemhelp.tbl
class ConditionHelpData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
        ('str20',     'S'),
    )


class SkillEffectTypeHelpData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )


class SkillEffectHelpData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('arr32_10',  'A4'),
        ('uint32_1c', 'I'),
        ('str20',     'S'),
        ('str28',     'S'),
        ('str30',     'S'),
        ('str38',     'S'),
        ('uint32_40', 'I'),
        ('uint32_44', 'I'),
        ('str48',     'S'),
        ('str50',     'S'),
    )


class AttrTypeHelpData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )


class SkillTypeHelpData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )


class SkillRangeHelpData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
        ('str18',     'S'),
        ('str20',     'S'),
    )


class ItemKindHelpData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
        ('str18',     'S'),
    )


class SkillItemStatusData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
        ('uint64_20', 'Q'),
        ('str28',     'S'),
    )


class SkillConnectListData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('arr16_08',  'A2'),
        ('uint32_14', 'I'),
    )


class SkillTextArrayData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )


class SkillRangeData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('float32_04', 'f'),
        ('float32_08', 'f'),
        ('float32_0c', 'f'),
        ('float32_10', 'f'),
    )


# t_lookpoint.tbl
class LookPointTableData(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
        ('arr16_20',  'A2'),
        ('uint32_2c', 'I'),
        ('arr16_30',  'A2'),
        ('uint32_3c', 'I'),
    )


# t_mapjump.tbl
class MapJumpAreaData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('uint32_04',  'I'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('float32_18', 'f'),
        ('float32_1c', 'f'),
        ('float32_20', 'f'),
        ('uint32_24',  'I'),
        ('str28',      'S'),
        ('str30',      'S'),
    )


class MapJumpSpotData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('uint32_04',  'I'),
        ('uint64_08',  'Q'),
        ('str10',      'S'),
        ('uint64_18',  'Q'),
        ('str20',      'S'),
        ('float32_28', 'f'),
        ('float32_2c', 'f'),
        ('float32_30', 'f'),
        ('uint32_34',  'I'),
        ('str38',      'S'),
        ('uint32_40',  'I'),
        ('float32_44', 'f'),
        ('float32_48', 'f'),
        ('float32_4c', 'f'),
        ('float32_50', 'f'),
        ('uint32_54',  'I'),
        ('str58',      'S'),
        ('uint64_60',  'Q'),
        ('str68',      'S'),
        ('arr16_70',   'A2'),
        ('uint32_7c',  'I'),
        ('arr16_80',   'A2'),
        ('uint32_8c',  'I'),
        ('str90',      'S'),
    )


# t_marker.tbl
class MarkerTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('arr32_08',   'A4'),
        ('uint32_14',  'I'),
        ('arr16_18',   'A2'),
        ('uint32_24',  'I'),
        ('arr16_28',   'A2'),
        ('uint32_34',  'I'),
        ('uint64_38',  'Q'),
        ('str40',      'S'),
        ('uint32_48',  'I'),
        ('float32_4c', 'f'),
        ('float32_50', 'f'),
        ('float32_54', 'f'),
        ('float32_58', 'f'),
        ('float32_5c', 'f'),
        ('float32_60', 'f'),
        ('uint32_64',  'I'),
        ('str68',      'S'),
    )


# t_minigame_blackjack.tbl
class BlackJackMessage(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )


class BlackJackMedal(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
    )


class BlackJackHelp(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class BlackJackProb(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
    )


# t_minigame_card_battler.tbl
class CardData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
    )


class CardEffectText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )


class CardAttributeData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class AITypeList(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
    )


class CardBattlerMessage(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('uint32_04',  'I'),
        ('str08',      'S'),
        ('uint32_10',  'I'),
        ('float32_14', 'f'),
    )


class ScoreCoefficient(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
    )


class LogText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


# t_minigame_fishing.tbl
class FishInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('uint32_10',  'I'),
        ('uint32_14',  'I'),
        ('uint32_18',  'I'),
        ('uint32_1c',  'I'),
        ('uint32_20',  'I'),
        ('uint32_24',  'I'),
        ('uint32_28',  'I'),
        ('uint32_2c',  'I'),
        ('uint64_30',  'Q'),
        ('uint64_38',  'Q'),
        ('uint64_40',  'Q'),
        ('uint32_48',  'I'),
        ('uint32_4c',  'I'),
        ('uint64_50',  'Q'),
        ('uint64_58',  'Q'),
        ('uint64_60',  'Q'),
        ('uint32_68',  'I'),
        ('uint32_6c',  'I'),
        ('uint64_70',  'Q'),
        ('uint64_78',  'Q'),
        ('uint64_80',  'Q'),
        ('float32_88', 'f'),
        ('float32_8c', 'f'),
        ('float32_90', 'f'),
        ('float32_94', 'f'),
        ('float32_98', 'f'),
        ('uint32_9c',  'I'),
        ('stra0',      'S'),
    )


class FishingConstant(TableDataEntry):
    DESCRIPTOR = (
        ('float32_00', 'f'),
        ('float32_04', 'f'),
        ('float32_08', 'f'),
        ('float32_0c', 'f'),
        ('float32_10', 'f'),
        ('float32_14', 'f'),
    )


class FishingCastInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('float32_04', 'f'),
        ('float32_08', 'f'),
    )


class FishingSpot(TableDataEntry):
    DESCRIPTOR = (
        ('str00',      'S'),
        ('str08',      'S'),
        ('uint64_10',  'Q'),
        ('arr16_18',   'A2'),
        ('uint32_24',  'I'),
        ('arr16_28',   'A2'),
        ('uint32_34',  'I'),
        ('uint64_38',  'Q'),
        ('uint32_40',  'I'),
        ('uint32_44',  'I'),
        ('uint32_48',  'I'),
        ('uint32_4c',  'I'),
        ('uint64_50',  'Q'),
        ('uint64_58',  'Q'),
        ('uint32_60',  'I'),
        ('uint32_64',  'I'),
        ('uint64_68',  'Q'),
        ('uint64_70',  'Q'),
        ('uint64_78',  'Q'),
        ('uint64_80',  'Q'),
        ('uint64_88',  'Q'),
        ('uint64_90',  'Q'),
        ('uint64_98',  'Q'),
        ('uint64_a0',  'Q'),
        ('uint64_a8',  'Q'),
        ('uint64_b0',  'Q'),
        ('uint64_b8',  'Q'),
        ('uint64_c0',  'Q'),
        ('uint64_c8',  'Q'),
        ('uint64_d0',  'Q'),
        ('uint64_d8',  'Q'),
        ('uint64_e0',  'Q'),
        ('uint64_e8',  'Q'),
        ('uint64_f0',  'Q'),
        ('uint64_f8',  'Q'),
        ('uint64_100', 'Q'),
        ('uint64_108', 'Q'),
        ('uint64_110', 'Q'),
        ('uint64_118', 'Q'),
        ('uint64_120', 'Q'),
        ('uint64_128', 'Q'),
        ('uint64_130', 'Q'),
        ('uint64_138', 'Q'),
        ('uint64_140', 'Q'),
        ('uint64_148', 'Q'),
        ('uint64_150', 'Q'),
        ('uint64_158', 'Q'),
        ('uint64_160', 'Q'),
        ('uint64_168', 'Q'),
        ('uint64_170', 'Q'),
        ('uint64_178', 'Q'),
        ('uint64_180', 'Q'),
        ('uint64_188', 'Q'),
        ('uint64_190', 'Q'),
        ('uint64_198', 'Q'),
        ('uint64_1a0', 'Q'),
        ('uint64_1a8', 'Q'),
        ('uint64_1b0', 'Q'),
    )


# t_minigame_poker.tbl
class PokerMessage(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )


class PokerMedal(TableDataEntry):
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


class PokerHelp(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


class PokerTrickLevel(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
    )


# t_notemenu.tbl
class NoteMainCategory(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )


class NoteMainBadge(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
    )


class NoteMainAffiliation(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('uint64_08', 'Q'),
    )


class NoteMainHistory(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('uint64_08', 'Q'),
    )


class NoteBattleCategory(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )


class NoteCookCategory(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
    )


class NoteHelpCategory(TableDataEntry):
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
        ('uint64_10', 'Q'),
        ('str18',     'S'),
        ('str20',     'S'),
    )


class NoteCookChara(TableDataEntry):
    DESCRIPTOR = (
        ('uint16_00', 'W'),
    )


class NoteCookItem(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('str10',     'S'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('str20',     'S'),
        ('arr8_28',   'A1'),
        ('uint32_34', 'I'),
    )


class NoteCookRecipe(TableDataEntry):
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
        ('uint32_34', 'I'),
        ('uint32_38', 'I'),
        ('uint32_3c', 'I'),
        ('uint32_40', 'I'),
    )


class NoteCookBonusChara(TableDataEntry):
    DESCRIPTOR = (
        ('uint16_00', 'W'),
    )


# t_orbment.tbl
class OrbmentSlotParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
    )


class QuartzParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('uint32_20', 'I'),
        ('uint32_24', 'I'),
    )


class ArtsParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint64_08', 'Q'),
    )


class AttrData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('str10',     'S'),
    )


# t_place.tbl
class PlaceTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('str18',      'S'),
        ('float32_20', 'f'),
        ('float32_24', 'f'),
        ('float32_28', 'f'),
        ('uint32_2c',  'I'),
        ('arr16_30',   'A2'),
        ('uint32_3c',  'I'),
        ('arr16_40',   'A2'),
        ('float32_4c', 'f'),
        ('uint32_50',  'I'),
        ('uint32_54',  'I'),
        ('str58',      'S'),
        ('str60',      'S'),
        ('str68',      'S'),
        ('float32_70', 'f'),
        ('float32_74', 'f'),
        ('arr32_78',   'A4'),
        ('float32_84', 'f'),
        ('float32_88', 'f'),
        ('float32_8c', 'f'),
        ('uint32_90',  'I'),
        ('uint32_94',  'I'),
        ('uint32_98',  'I'),
        ('float32_9c', 'f'),
        ('float32_a0', 'f'),
        ('float32_a4', 'f'),
    )


# t_popup_face.tbl
class PopupFaceParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
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


# t_quest.tbl
class QuestRank(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
    )


class QuestChapterRank(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint32_10', 'I'),
    )


class QuestTitle(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('uint64_18', 'Q'),
        ('str20',     'S'),
        ('uint32_28', 'I'),
        ('uint32_2c', 'I'),
        ('uint32_30', 'I'),
        ('uint32_34', 'I'),
        ('uint32_38', 'I'),
        ('uint32_3c', 'I'),
        ('uint32_40', 'I'),
        ('uint32_44', 'I'),
        ('uint64_48', 'Q'),
        ('str50',     'S'),
        ('str58',     'S'),
        ('uint64_60', 'Q'),
    )


class QuestText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
        ('str18',     'S'),
    )


class NaviText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('arr32_18',  'A4'),
        ('uint32_24', 'I'),
        ('arr32_28',  'A4'),
        ('uint32_34', 'I'),
    )


class QuestReportVoice(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('arr32_08',  'A4'),
        ('uint32_14', 'I'),
        ('arr32_18',  'A4'),
        ('uint32_24', 'I'),
        ('arr32_28',  'A4'),
        ('uint32_34', 'I'),
        ('arr32_38',  'A4'),
        ('uint32_44', 'I'),
        ('arr32_48',  'A4'),
        ('uint32_54', 'I'),
    )


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


# t_se.tbl
class SETableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('uint32_10',  'I'),
        ('float32_14', 'f'),
        ('uint32_18',  'I'),
        ('float32_1c', 'f'),
    )


# t_shop.tbl
class ShopInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('uint64_10',  'Q'),
        ('str18',      'S'),
        ('uint32_20',  'I'),
        ('float32_24', 'f'),
        ('float32_28', 'f'),
        ('float32_2c', 'f'),
        ('float32_30', 'f'),
        ('float32_34', 'f'),
        ('uint32_38',  'I'),
        ('float32_3c', 'f'),
        ('float32_40', 'f'),
        ('uint32_44',  'I'),
    )


class ShopItem(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('arr16_08',  'A2'),
        ('uint32_14', 'I'),
        ('arr16_18',  'A2'),
        ('uint32_24', 'I'),
    )


class ShopTypeDesc(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
    )


class ShopConv(TableDataEntry):
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
    )


class TradeItem(TableDataEntry):
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
        ('uint32_30', 'I'),
    )


class CharaSettingInfo(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('float32_04', 'f'),
        ('float32_08', 'f'),
        ('float32_0c', 'f'),
        ('float32_10', 'f'),
    )


class CharaArrange(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('uint32_04',  'I'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('float32_18', 'f'),
        ('uint32_1c',  'I'),
        ('uint32_20',  'I'),
        ('float32_24', 'f'),
        ('str28',      'S'),
        ('uint32_30',  'I'),
        ('float32_34', 'f'),
        ('uint64_38',  'Q'),
    )


# t_skill.tbl
class SkillParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('uint64_10',  'Q'),
        ('str18',      'S'),
        ('uint32_20',  'I'),
        ('float32_24', 'f'),
        ('float32_28', 'f'),
        ('float32_2c', 'f'),
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
        ('float32_80', 'f'),
        ('uint32_84',  'I'),
        ('uint32_88',  'I'),
        ('uint32_8c',  'I'),
        ('str90',      'S'),
        ('str98',      'S'),
        ('stra0',      'S'),
        ('stra8',      'S'),
    )


class SkillPowerIcon(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('str08',     'S'),
    )


# t_status.tbl
class StatusParam(TableDataEntry):
    DESCRIPTOR = (
        ('str00',       'S'),
        ('str08',       'S'),
        ('uint64_10',   'Q'),
        ('str18',       'S'),
        ('str20',       'S'),
        ('str28',       'S'),
        ('str30',       'S'),
        ('str38',       'S'),
        ('str40',       'S'),
        ('uint32_48',   'I'),
        ('float32_4c',  'f'),
        ('float32_50',  'f'),
        ('float32_54',  'f'),
        ('float32_58',  'f'),
        ('float32_5c',  'f'),
        ('float32_60',  'f'),
        ('float32_64',  'f'),
        ('float32_68',  'f'),
        ('float32_6c',  'f'),
        ('float32_70',  'f'),
        ('float32_74',  'f'),
        ('float32_78',  'f'),
        ('float32_7c',  'f'),
        ('float32_80',  'f'),
        ('float32_84',  'f'),
        ('float32_88',  'f'),
        ('float32_8c',  'f'),
        ('str90',       'S'),
        ('uint64_98',   'Q'),
        ('uint32_a0',   'I'),
        ('float32_a4',  'f'),
        ('float32_a8',  'f'),
        ('float32_ac',  'f'),
        ('float32_b0',  'f'),
        ('float32_b4',  'f'),
        ('float32_b8',  'f'),
        ('float32_bc',  'f'),
        ('float32_c0',  'f'),
        ('float32_c4',  'f'),
        ('uint32_c8',   'I'),
        ('float32_cc',  'f'),
        ('float32_d0',  'f'),
        ('float32_d4',  'f'),
        ('uint32_d8',   'I'),
        ('uint32_dc',   'I'),
        ('float32_e0',  'f'),
        ('uint32_e4',   'I'),
        ('float32_e8',  'f'),
        ('uint32_ec',   'I'),
        ('uint64_f0',   'Q'),
        ('uint32_f8',   'I'),
        ('float32_fc',  'f'),
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
        ('uint32_134',  'I'),
        ('uint32_138',  'I'),
        ('uint32_13c',  'I'),
        ('uint32_140',  'I'),
        ('uint32_144',  'I'),
        ('uint32_148',  'I'),
        ('uint32_14c',  'I'),
        ('uint32_150',  'I'),
        ('uint32_154',  'I'),
        ('uint32_158',  'I'),
        ('uint32_15c',  'I'),
        ('uint32_160',  'I'),
        ('uint32_164',  'I'),
        ('uint32_168',  'I'),
        ('uint32_16c',  'I'),
        ('uint32_170',  'I'),
        ('uint32_174',  'I'),
        ('uint32_178',  'I'),
        ('uint32_17c',  'I'),
        ('uint32_180',  'I'),
        ('uint32_184',  'I'),
        ('uint64_188',  'Q'),
        ('str190',      'S'),
        ('str198',      'S'),
    )


# t_support_ability.tbl
class SupportAbilityParam(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint64_08', 'Q'),
        ('uint32_10', 'I'),
        ('uint32_14', 'I'),
        ('uint64_18', 'Q'),
        ('str20',     'S'),
        ('str28',     'S'),
        ('str30',     'S'),
        ('str38',     'S'),
    )


class SupportLevelData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
    )


# t_tbox.tbl
class TBoxParam(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
        ('str18',     'S'),
        ('str20',     'S'),
        ('uint64_28', 'Q'),
        ('arr16_30',  'A2'),
        ('uint32_3c', 'I'),
        ('uint64_40', 'Q'),
        ('arr16_48',  'A2'),
        ('uint32_54', 'I'),
    )


# t_text.tbl
class TextTableData(TableDataEntry):
    DESCRIPTOR = (
        ('str00', 'S'),
        ('str08', 'S'),
    )


# t_tips.tbl
class TipsTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('arr16_08',  'A2'),
        ('uint32_14', 'I'),
        ('str18',     'S'),
        ('uint32_20', 'I'),
        ('uint32_24', 'I'),
        ('str28',     'S'),
        ('str30',     'S'),
    )


# t_title.tbl
class TitleTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('str18',      'S'),
        ('uint32_20',  'I'),
        ('float32_24', 'f'),
        ('str28',      'S'),
        ('float32_30', 'f'),
        ('uint32_34',  'I'),
    )


# t_uds.tbl
class UDSActivityData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )


# t_voice.tbl
class VoiceTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('uint32_10',  'I'),
        ('float32_14', 'f'),
        ('uint32_18',  'I'),
        ('float32_1c', 'f'),
        ('str20',      'S'),
    )
