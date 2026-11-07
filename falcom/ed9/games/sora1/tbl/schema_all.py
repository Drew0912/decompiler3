"""sora1's .tbl record classes, the base of sora2's, one file per section: falcom/ed9/parser/tbl.py reads a section
through them. Fields named by offset have no known meaning yet"""

from falcom.ed9.parser.tbl import RawSection, RawTableEntry, create_tbl    # for generated scripts' star import

# A DESCRIPTOR's kinds, defined in FIELD_KINDS (falcom/ed9/parser/tbl.py); integers are unsigned but for b, w and i
#   b   Byte: 1-byte signed integer, printed in decimal
#   B   Byte: 1-byte integer, printed in decimal
#   w   Word: 2-byte signed integer, printed in decimal
#   W   Word: 2-byte integer, printed in hex
#   H   Half: 2-byte integer, printed in decimal
#   i   Int: 4-byte signed integer, printed in decimal
#   I   Int: 4-byte integer, printed in decimal
#   Q   Quad: 8-byte integer, printed in decimal
#   f   float: 4 bytes
#   S   String: 8-byte pointer to a NUL-ended string in the data block
#   A1  Array of 1-byte integers: 8-byte pointer into the data block, 4-byte element count
#   A2  Array of 2-byte integers: the same
#   A4  Array of 4-byte integers: the same
#   AF  Array of 4-byte floats: the same
#   P1  Padding: 1 zero byte, not a field of a row; P2 to P7 the same

from falcom.ed9.games.sora1.tbl.schema.AITypeList import AITypeList
from falcom.ed9.games.sora1.tbl.schema.ATBonusParam import ATBonusParam
from falcom.ed9.games.sora1.tbl.schema.ATBonusSet import ATBonusSet
from falcom.ed9.games.sora1.tbl.schema.AchievementCategoryData import AchievementCategoryData
from falcom.ed9.games.sora1.tbl.schema.AchievementTableData import AchievementTableData
from falcom.ed9.games.sora1.tbl.schema.ActiveVoiceTableData import ActiveVoiceTableData
from falcom.ed9.games.sora1.tbl.schema.AniParam import AniParam
from falcom.ed9.games.sora1.tbl.schema.ArtsParam import ArtsParam
from falcom.ed9.games.sora1.tbl.schema.AttrData import AttrData
from falcom.ed9.games.sora1.tbl.schema.AttrTypeHelpData import AttrTypeHelpData
from falcom.ed9.games.sora1.tbl.schema.BGMTableData import BGMTableData
from falcom.ed9.games.sora1.tbl.schema.BTLVoiceTable import BTLVoiceTable
from falcom.ed9.games.sora1.tbl.schema.BattleBGM import BattleBGM
from falcom.ed9.games.sora1.tbl.schema.BattleEnemyDamageAdjust import BattleEnemyDamageAdjust
from falcom.ed9.games.sora1.tbl.schema.BattleEnemyLevelAdjust import BattleEnemyLevelAdjust
from falcom.ed9.games.sora1.tbl.schema.BattleEnemyLevelStatusAdjust import BattleEnemyLevelStatusAdjust
from falcom.ed9.games.sora1.tbl.schema.BattleLevelField import BattleLevelField
from falcom.ed9.games.sora1.tbl.schema.BattleLevelTurn import BattleLevelTurn
from falcom.ed9.games.sora1.tbl.schema.BattleSCraftDamageRatio import BattleSCraftDamageRatio
from falcom.ed9.games.sora1.tbl.schema.BlackJackHelp import BlackJackHelp
from falcom.ed9.games.sora1.tbl.schema.BlackJackMedal import BlackJackMedal
from falcom.ed9.games.sora1.tbl.schema.BlackJackMessage import BlackJackMessage
from falcom.ed9.games.sora1.tbl.schema.BlackJackProb import BlackJackProb
from falcom.ed9.games.sora1.tbl.schema.BooksCategory import BooksCategory
from falcom.ed9.games.sora1.tbl.schema.BooksText import BooksText
from falcom.ed9.games.sora1.tbl.schema.BooksTitle import BooksTitle
from falcom.ed9.games.sora1.tbl.schema.BreakObjectTableData import BreakObjectTableData
from falcom.ed9.games.sora1.tbl.schema.CardAttributeData import CardAttributeData
from falcom.ed9.games.sora1.tbl.schema.CardBattlerMessage import CardBattlerMessage
from falcom.ed9.games.sora1.tbl.schema.CardData import CardData
from falcom.ed9.games.sora1.tbl.schema.CardEffectText import CardEffectText
from falcom.ed9.games.sora1.tbl.schema.ChapterParam import ChapterParam
from falcom.ed9.games.sora1.tbl.schema.CharaArrange import CharaArrange
from falcom.ed9.games.sora1.tbl.schema.CharaSettingInfo import CharaSettingInfo
from falcom.ed9.games.sora1.tbl.schema.ChrDataParam import ChrDataParam
from falcom.ed9.games.sora1.tbl.schema.CollisionFootStepInfo import CollisionFootStepInfo
from falcom.ed9.games.sora1.tbl.schema.ConditionHelpData import ConditionHelpData
from falcom.ed9.games.sora1.tbl.schema.ConditionInfoTableData import ConditionInfoTableData
from falcom.ed9.games.sora1.tbl.schema.ConditionTypeParam import ConditionTypeParam
from falcom.ed9.games.sora1.tbl.schema.CostumeAttachOffset import CostumeAttachOffset
from falcom.ed9.games.sora1.tbl.schema.CostumeParam import CostumeParam
from falcom.ed9.games.sora1.tbl.schema.DLCTableData import DLCTableData
from falcom.ed9.games.sora1.tbl.schema.EffectTableData import EffectTableData
from falcom.ed9.games.sora1.tbl.schema.EventBoxTableData import EventBoxTableData
from falcom.ed9.games.sora1.tbl.schema.EventGroupData import EventGroupData
from falcom.ed9.games.sora1.tbl.schema.EventSubGroupData import EventSubGroupData
from falcom.ed9.games.sora1.tbl.schema.EventTableData import EventTableData
from falcom.ed9.games.sora1.tbl.schema.EyeAttachData import EyeAttachData
from falcom.ed9.games.sora1.tbl.schema.EyeBallSizePatternNameData import EyeBallSizePatternNameData
from falcom.ed9.games.sora1.tbl.schema.EyeBrowsPatternNameData import EyeBrowsPatternNameData
from falcom.ed9.games.sora1.tbl.schema.EyeDirPatternNameData import EyeDirPatternNameData
from falcom.ed9.games.sora1.tbl.schema.EyeLidsPatternNameData import EyeLidsPatternNameData
from falcom.ed9.games.sora1.tbl.schema.EyeModifyAttachData import EyeModifyAttachData
from falcom.ed9.games.sora1.tbl.schema.EyeModifyPatternNameData import EyeModifyPatternNameData
from falcom.ed9.games.sora1.tbl.schema.EyePresetData import EyePresetData
from falcom.ed9.games.sora1.tbl.schema.EyeScaleData import EyeScaleData
from falcom.ed9.games.sora1.tbl.schema.FaceAnimeData import FaceAnimeData
from falcom.ed9.games.sora1.tbl.schema.FaceTexturePatternNameData import FaceTexturePatternNameData
from falcom.ed9.games.sora1.tbl.schema.FieldItemTableData import FieldItemTableData
from falcom.ed9.games.sora1.tbl.schema.FishInfo import FishInfo
from falcom.ed9.games.sora1.tbl.schema.FishingCastInfo import FishingCastInfo
from falcom.ed9.games.sora1.tbl.schema.FishingConstant import FishingConstant
from falcom.ed9.games.sora1.tbl.schema.FishingSpot import FishingSpot
from falcom.ed9.games.sora1.tbl.schema.GraphicsPresetTableData import GraphicsPresetTableData
from falcom.ed9.games.sora1.tbl.schema.HelpController import HelpController
from falcom.ed9.games.sora1.tbl.schema.HelpIconList import HelpIconList
from falcom.ed9.games.sora1.tbl.schema.HelpOverlayIcon import HelpOverlayIcon
from falcom.ed9.games.sora1.tbl.schema.HelpPage import HelpPage
from falcom.ed9.games.sora1.tbl.schema.HelpTitle import HelpTitle
from falcom.ed9.games.sora1.tbl.schema.ItemKindHelpData import ItemKindHelpData
from falcom.ed9.games.sora1.tbl.schema.ItemKindParam2 import ItemKindParam2
from falcom.ed9.games.sora1.tbl.schema.ItemShopTabType import ItemShopTabType
from falcom.ed9.games.sora1.tbl.schema.ItemTabType import ItemTabType
from falcom.ed9.games.sora1.tbl.schema.ItemTableData import ItemTableData
from falcom.ed9.games.sora1.tbl.schema.LogText import LogText
from falcom.ed9.games.sora1.tbl.schema.LookPointTableData import LookPointTableData
from falcom.ed9.games.sora1.tbl.schema.MapBGM import MapBGM
from falcom.ed9.games.sora1.tbl.schema.MapJumpAreaData import MapJumpAreaData
from falcom.ed9.games.sora1.tbl.schema.MapJumpSpotData import MapJumpSpotData
from falcom.ed9.games.sora1.tbl.schema.MarkerTableData import MarkerTableData
from falcom.ed9.games.sora1.tbl.schema.MonsterSettingParam import MonsterSettingParam
from falcom.ed9.games.sora1.tbl.schema.MouthPatternMap import MouthPatternMap
from falcom.ed9.games.sora1.tbl.schema.MouthPatternNameData import MouthPatternNameData
from falcom.ed9.games.sora1.tbl.schema.NPCParam import NPCParam, NPCParam98
from falcom.ed9.games.sora1.tbl.schema.NameTableData import NameTableData
from falcom.ed9.games.sora1.tbl.schema.NaviText import NaviText
from falcom.ed9.games.sora1.tbl.schema.NoteBattleCategory import NoteBattleCategory
from falcom.ed9.games.sora1.tbl.schema.NoteCookBonusChara import NoteCookBonusChara
from falcom.ed9.games.sora1.tbl.schema.NoteCookCategory import NoteCookCategory
from falcom.ed9.games.sora1.tbl.schema.NoteCookChara import NoteCookChara
from falcom.ed9.games.sora1.tbl.schema.NoteCookItem import NoteCookItem
from falcom.ed9.games.sora1.tbl.schema.NoteCookRecipe import NoteCookRecipe
from falcom.ed9.games.sora1.tbl.schema.NoteHelpCategory import NoteHelpCategory
from falcom.ed9.games.sora1.tbl.schema.NoteMainAffiliation import NoteMainAffiliation
from falcom.ed9.games.sora1.tbl.schema.NoteMainBadge import NoteMainBadge
from falcom.ed9.games.sora1.tbl.schema.NoteMainCategory import NoteMainCategory
from falcom.ed9.games.sora1.tbl.schema.NoteMainHistory import NoteMainHistory
from falcom.ed9.games.sora1.tbl.schema.NoteMonsRecordData import NoteMonsRecordData
from falcom.ed9.games.sora1.tbl.schema.OrbmentSlotParam import OrbmentSlotParam
from falcom.ed9.games.sora1.tbl.schema.OverDriveEffect import OverDriveEffect
from falcom.ed9.games.sora1.tbl.schema.PlaceTableData import PlaceTableData
from falcom.ed9.games.sora1.tbl.schema.PlayRecordData import PlayRecordData
from falcom.ed9.games.sora1.tbl.schema.PokerHelp import PokerHelp
from falcom.ed9.games.sora1.tbl.schema.PokerMedal import PokerMedal
from falcom.ed9.games.sora1.tbl.schema.PokerMessage import PokerMessage
from falcom.ed9.games.sora1.tbl.schema.PokerTrickLevel import PokerTrickLevel
from falcom.ed9.games.sora1.tbl.schema.PopupFaceParam import PopupFaceParam
from falcom.ed9.games.sora1.tbl.schema.PortraitDataParam import PortraitDataParam
from falcom.ed9.games.sora1.tbl.schema.QuartzParam import QuartzParam
from falcom.ed9.games.sora1.tbl.schema.QuestChapterRank import QuestChapterRank
from falcom.ed9.games.sora1.tbl.schema.QuestRank import QuestRank
from falcom.ed9.games.sora1.tbl.schema.QuestReportVoice import QuestReportVoice
from falcom.ed9.games.sora1.tbl.schema.QuestText import QuestText
from falcom.ed9.games.sora1.tbl.schema.QuestTitle import QuestTitle
from falcom.ed9.games.sora1.tbl.schema.RealTimeHelpTableData import RealTimeHelpTableData
from falcom.ed9.games.sora1.tbl.schema.SETableData import SETableData
from falcom.ed9.games.sora1.tbl.schema.SceneCommonSetting import SceneCommonSetting
from falcom.ed9.games.sora1.tbl.schema.SceneSkySetting import SceneSkySetting
from falcom.ed9.games.sora1.tbl.schema.ScoreCoefficient import ScoreCoefficient
from falcom.ed9.games.sora1.tbl.schema.ShopConv import ShopConv
from falcom.ed9.games.sora1.tbl.schema.ShopInfo import ShopInfo
from falcom.ed9.games.sora1.tbl.schema.ShopItem import ShopItem
from falcom.ed9.games.sora1.tbl.schema.ShopTypeDesc import ShopTypeDesc
from falcom.ed9.games.sora1.tbl.schema.SkillConnectListData import SkillConnectListData
from falcom.ed9.games.sora1.tbl.schema.SkillEffectHelpData import SkillEffectHelpData
from falcom.ed9.games.sora1.tbl.schema.SkillEffectTypeHelpData import SkillEffectTypeHelpData
from falcom.ed9.games.sora1.tbl.schema.SkillItemStatusData import SkillItemStatusData
from falcom.ed9.games.sora1.tbl.schema.SkillParam import SkillParam
from falcom.ed9.games.sora1.tbl.schema.SkillPowerIcon import SkillPowerIcon
from falcom.ed9.games.sora1.tbl.schema.SkillRangeData import SkillRangeData
from falcom.ed9.games.sora1.tbl.schema.SkillRangeHelpData import SkillRangeHelpData
from falcom.ed9.games.sora1.tbl.schema.SkillTextArrayData import SkillTextArrayData
from falcom.ed9.games.sora1.tbl.schema.SkillTypeHelpData import SkillTypeHelpData
from falcom.ed9.games.sora1.tbl.schema.StatusParam import StatusParam
from falcom.ed9.games.sora1.tbl.schema.SupportAbilityParam import SupportAbilityParam
from falcom.ed9.games.sora1.tbl.schema.SupportLevelData import SupportLevelData
from falcom.ed9.games.sora1.tbl.schema.TBoxParam import TBoxParam
from falcom.ed9.games.sora1.tbl.schema.TacticalBonus import TacticalBonus
from falcom.ed9.games.sora1.tbl.schema.TalkChrData import TalkChrData
from falcom.ed9.games.sora1.tbl.schema.TextTableData import TextTableData
from falcom.ed9.games.sora1.tbl.schema.TipsTableData import TipsTableData
from falcom.ed9.games.sora1.tbl.schema.TitleTableData import TitleTableData
from falcom.ed9.games.sora1.tbl.schema.TradeItem import TradeItem
from falcom.ed9.games.sora1.tbl.schema.UDSActivityData import UDSActivityData
from falcom.ed9.games.sora1.tbl.schema.VoiceTableData import VoiceTableData
from falcom.ed9.games.sora1.tbl.schema.WeedingTableData import WeedingTableData
