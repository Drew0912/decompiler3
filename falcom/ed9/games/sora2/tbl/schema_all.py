"""sora2's .tbl record classes, one file per section: sora1's, plus what differs here (a class of the same name
replaces sora1's)"""

from falcom.ed9.games.sora1.tbl.schema_all import *

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

from falcom.ed9.games.sora2.tbl.schema.BattleLevelEnemyAdjust import BattleLevelEnemyAdjust
from falcom.ed9.games.sora2.tbl.schema.BattleLevelTurn import BattleLevelTurn
from falcom.ed9.games.sora2.tbl.schema.BlackJackInfo import BlackJackInfo
from falcom.ed9.games.sora2.tbl.schema.BlackJackMessage import BlackJackMessage
from falcom.ed9.games.sora2.tbl.schema.BlackJackRollRate import BlackJackRollRate
from falcom.ed9.games.sora2.tbl.schema.BlackJackRuleText import BlackJackRuleText
from falcom.ed9.games.sora2.tbl.schema.BreakObjectTableData import BreakObjectTableData
from falcom.ed9.games.sora2.tbl.schema.CharaArrange import CharaArrange
from falcom.ed9.games.sora2.tbl.schema.ChrDataParam import ChrDataParam
from falcom.ed9.games.sora2.tbl.schema.FishInfo import FishInfo
from falcom.ed9.games.sora2.tbl.schema.FishingBaitInfo import FishingBaitInfo
from falcom.ed9.games.sora2.tbl.schema.FishingConstant import FishingConstant
from falcom.ed9.games.sora2.tbl.schema.FishingRodInfo import FishingRodInfo
from falcom.ed9.games.sora2.tbl.schema.FishingSpot import FishingSpot
from falcom.ed9.games.sora2.tbl.schema.ItemTableData import ItemTableData
from falcom.ed9.games.sora2.tbl.schema.LipSyncData import LipSyncData
from falcom.ed9.games.sora2.tbl.schema.MapJumpChrIcon import MapJumpChrIcon
from falcom.ed9.games.sora2.tbl.schema.MedalItem import MedalItem
from falcom.ed9.games.sora2.tbl.schema.MonsterSettingParam import MonsterSettingParam, MonsterSettingParamA8
from falcom.ed9.games.sora2.tbl.schema.NaviText import NaviText
from falcom.ed9.games.sora2.tbl.schema.NoteCookChara import NoteCookChara
from falcom.ed9.games.sora2.tbl.schema.NoteFishingCategory import NoteFishingCategory
from falcom.ed9.games.sora2.tbl.schema.NoteMainHistory import NoteMainHistory8
from falcom.ed9.games.sora2.tbl.schema.NoteMainPartnerInfo import NoteMainPartnerInfo
from falcom.ed9.games.sora2.tbl.schema.NoteMonsRecordData import NoteMonsRecordData
from falcom.ed9.games.sora2.tbl.schema.OrbmentSlotParam import OrbmentSlotParam
from falcom.ed9.games.sora2.tbl.schema.OutItemList import OutItemList
from falcom.ed9.games.sora2.tbl.schema.PokerInfo import PokerInfo
from falcom.ed9.games.sora2.tbl.schema.PokerMessage import PokerMessage
from falcom.ed9.games.sora2.tbl.schema.PokerRollRate import PokerRollRate
from falcom.ed9.games.sora2.tbl.schema.PokerRuleText import PokerRuleText
from falcom.ed9.games.sora2.tbl.schema.PortraitDataParam import PortraitDataParam
from falcom.ed9.games.sora2.tbl.schema.QuestRankBefore import QuestRankBefore
from falcom.ed9.games.sora2.tbl.schema.QuestText import QuestText38
from falcom.ed9.games.sora2.tbl.schema.RouletteBetExplain import RouletteBetExplain
from falcom.ed9.games.sora2.tbl.schema.RouletteBetRate import RouletteBetRate
from falcom.ed9.games.sora2.tbl.schema.RouletteCheat import RouletteCheat
from falcom.ed9.games.sora2.tbl.schema.RouletteInfo import RouletteInfo
from falcom.ed9.games.sora2.tbl.schema.RouletteMessage import RouletteMessage
from falcom.ed9.games.sora2.tbl.schema.RouletteNumber import RouletteNumber
from falcom.ed9.games.sora2.tbl.schema.RouletteRuleText import RouletteRuleText
from falcom.ed9.games.sora2.tbl.schema.SkillGetParam import SkillGetParam
from falcom.ed9.games.sora2.tbl.schema.SlotBattleEvent import SlotBattleEvent
from falcom.ed9.games.sora2.tbl.schema.SlotBonus import SlotBonus
from falcom.ed9.games.sora2.tbl.schema.SlotCheat import SlotCheat
from falcom.ed9.games.sora2.tbl.schema.SlotEvent import SlotEvent
from falcom.ed9.games.sora2.tbl.schema.SlotInfo import SlotInfo
from falcom.ed9.games.sora2.tbl.schema.SlotMonsterInfo import SlotMonsterInfo
from falcom.ed9.games.sora2.tbl.schema.SlotPomInfo import SlotPomInfo
from falcom.ed9.games.sora2.tbl.schema.SlotReelPattern import SlotReelPattern
from falcom.ed9.games.sora2.tbl.schema.SlotReelSpeed import SlotReelSpeed
from falcom.ed9.games.sora2.tbl.schema.SlotRoles import SlotRoles
from falcom.ed9.games.sora2.tbl.schema.SlotTBoxEvent import SlotTBoxEvent
from falcom.ed9.games.sora2.tbl.schema.SlotTBoxInfo import SlotTBoxInfo
from falcom.ed9.games.sora2.tbl.schema.StatusParam import StatusParam
from falcom.ed9.games.sora2.tbl.schema.TBoxParam import TBoxParam
from falcom.ed9.games.sora2.tbl.schema.TalkTableData import TalkTableData
from falcom.ed9.games.sora2.tbl.schema.ViewerAttachList import ViewerAttachList
from falcom.ed9.games.sora2.tbl.schema.ViewerBGMList import ViewerBGMList
from falcom.ed9.games.sora2.tbl.schema.ViewerCharaEquipList import ViewerCharaEquipList
from falcom.ed9.games.sora2.tbl.schema.ViewerCharaList import ViewerCharaList
from falcom.ed9.games.sora2.tbl.schema.ViewerCharaSelectList import ViewerCharaSelectList
from falcom.ed9.games.sora2.tbl.schema.ViewerCheekList import ViewerCheekList
from falcom.ed9.games.sora2.tbl.schema.ViewerCostumeList import ViewerCostumeList
from falcom.ed9.games.sora2.tbl.schema.ViewerEnvList import ViewerEnvList
from falcom.ed9.games.sora2.tbl.schema.ViewerEyeLineList import ViewerEyeLineList
from falcom.ed9.games.sora2.tbl.schema.ViewerFaceList import ViewerFaceList
from falcom.ed9.games.sora2.tbl.schema.ViewerHairList import ViewerHairList
from falcom.ed9.games.sora2.tbl.schema.ViewerMainList import ViewerMainList
from falcom.ed9.games.sora2.tbl.schema.ViewerMapData import ViewerMapData
from falcom.ed9.games.sora2.tbl.schema.ViewerMapList import ViewerMapList
from falcom.ed9.games.sora2.tbl.schema.ViewerMotionList import ViewerMotionList
from falcom.ed9.games.sora2.tbl.schema.ViewerMouseList import ViewerMouseList
from falcom.ed9.games.sora2.tbl.schema.ViewerNeckDirList import ViewerNeckDirList
from falcom.ed9.games.sora2.tbl.schema.ViewerShotList import ViewerShotList
from falcom.ed9.games.sora2.tbl.schema.ViewerSystemList import ViewerSystemList
from falcom.ed9.games.sora2.tbl.schema.ViewerWeaponList import ViewerWeaponList
