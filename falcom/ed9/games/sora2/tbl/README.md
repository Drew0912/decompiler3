# sora2 tables

Each table in `sora2/extracted/table_en/` and the schema classes that read it, in the order of its sections. A class
`sora2` defines is in this folder's `schema/`; a class the two games share is in `sora1`'s. A pattern row, such as
`t_mon_a*.tbl`, covers the files of that name that have no row of their own. More on the classes:
[TBL_FORMAT.md](../../../../../docs/falcom/ed9/TBL_FORMAT.md), "Record Classes".

| Table | Schemas |
|---|---|
| `t_achievement.tbl` | [AchievementTableData](../../sora1/tbl/schema/AchievementTableData.py), [AchievementCategoryData](../../sora1/tbl/schema/AchievementCategoryData.py), [PlayRecordData](../../sora1/tbl/schema/PlayRecordData.py) |
| `t_active_voice.tbl` | [ActiveVoiceTableData](../../sora1/tbl/schema/ActiveVoiceTableData.py) |
| `t_ani_param.tbl` | [AniParam](../../sora1/tbl/schema/AniParam.py) |
| `t_bgm.tbl` | [BGMTableData](../../sora1/tbl/schema/BGMTableData.py) |
| `t_bgmset.tbl` | [MapBGM](../../sora1/tbl/schema/MapBGM.py), [BattleBGM](../../sora1/tbl/schema/BattleBGM.py) |
| `t_books.tbl` | [BooksTitle](../../sora1/tbl/schema/BooksTitle.py), [BooksText](../../sora1/tbl/schema/BooksText.py), [BooksCategory](../../sora1/tbl/schema/BooksCategory.py) |
| `t_break_object.tbl` | [BreakObjectTableData](schema/BreakObjectTableData.py), [WeedingTableData](../../sora1/tbl/schema/WeedingTableData.py) |
| `t_btl_result_voice.tbl` | `BTResultTable`: no schema, read as raw hex |
| `t_btl_voice.tbl` | [BTLVoiceTable](../../sora1/tbl/schema/BTLVoiceTable.py) |
| `t_btlsys.tbl` | [ATBonusParam](../../sora1/tbl/schema/ATBonusParam.py), [ATBonusSet](../../sora1/tbl/schema/ATBonusSet.py), [BattleLevelField](../../sora1/tbl/schema/BattleLevelField.py), [BattleLevelTurn](schema/BattleLevelTurn.py), [BattleEnemyLevelStatusAdjust](../../sora1/tbl/schema/BattleEnemyLevelStatusAdjust.py), [BattleEnemyDamageAdjust](../../sora1/tbl/schema/BattleEnemyDamageAdjust.py), [BattleEnemyLevelAdjust](../../sora1/tbl/schema/BattleEnemyLevelAdjust.py), [BattleLevelEnemyAdjust](schema/BattleLevelEnemyAdjust.py), [BattleSCraftDamageRatio](../../sora1/tbl/schema/BattleSCraftDamageRatio.py), [TacticalBonus](../../sora1/tbl/schema/TacticalBonus.py) |
| `t_chapter.tbl` | [ChapterParam](../../sora1/tbl/schema/ChapterParam.py) |
| `t_chrdata.tbl` | [ChrDataParam](schema/ChrDataParam.py), [TalkChrData](../../sora1/tbl/schema/TalkChrData.py), [PortraitDataParam](schema/PortraitDataParam.py) |
| `t_collision_info.tbl` | [CollisionFootStepInfo](../../sora1/tbl/schema/CollisionFootStepInfo.py) |
| `t_condition_info.tbl` | [ConditionInfoTableData](../../sora1/tbl/schema/ConditionInfoTableData.py), [ConditionTypeParam](../../sora1/tbl/schema/ConditionTypeParam.py), [OverDriveEffect](../../sora1/tbl/schema/OverDriveEffect.py) |
| `t_constant_value.tbl` | [ConstantValue](../../sora1/tbl/schema/ConstantValue.py) |
| `t_costume.tbl` | [CostumeParam](../../sora1/tbl/schema/CostumeParam.py), [CostumeAttachOffset](../../sora1/tbl/schema/CostumeAttachOffset.py) |
| `t_dlc.tbl` | [DLCTableData](../../sora1/tbl/schema/DLCTableData.py) |
| `t_dlc_appid_convert.tbl` | [DLCAppIDConvertTableData](../../sora1/tbl/schema/DLCAppIDConvertTableData.py) |
| `t_effect.tbl` | [EffectTableData](../../sora1/tbl/schema/EffectTableData.py) |
| `t_eventbox.tbl` | [EventBoxTableData](../../sora1/tbl/schema/EventBoxTableData.py) |
| `t_evtable.tbl` | [EventGroupData](../../sora1/tbl/schema/EventGroupData.py), [EventSubGroupData](../../sora1/tbl/schema/EventSubGroupData.py), [EventTableData](../../sora1/tbl/schema/EventTableData.py) |
| `t_face_anime.tbl` | [FaceAnimeData](../../sora1/tbl/schema/FaceAnimeData.py), [LipSyncData](schema/LipSyncData.py), [EyePresetData](../../sora1/tbl/schema/EyePresetData.py), [EyeScaleData](../../sora1/tbl/schema/EyeScaleData.py), [MouthPatternMap](../../sora1/tbl/schema/MouthPatternMap.py), [EyeAttachData](../../sora1/tbl/schema/EyeAttachData.py), [EyeModifyAttachData](../../sora1/tbl/schema/EyeModifyAttachData.py), [EyeDirPatternNameData](../../sora1/tbl/schema/EyeDirPatternNameData.py), [EyeLidsPatternNameData](../../sora1/tbl/schema/EyeLidsPatternNameData.py), [EyeBrowsPatternNameData](../../sora1/tbl/schema/EyeBrowsPatternNameData.py), [EyeModifyPatternNameData](../../sora1/tbl/schema/EyeModifyPatternNameData.py), [MouthPatternNameData](../../sora1/tbl/schema/MouthPatternNameData.py), [EyeBallSizePatternNameData](../../sora1/tbl/schema/EyeBallSizePatternNameData.py), [FaceTexturePatternNameData](../../sora1/tbl/schema/FaceTexturePatternNameData.py) |
| `t_field_item.tbl` | [FieldItemTableData](../../sora1/tbl/schema/FieldItemTableData.py) |
| `t_graphics_preset.tbl` | [GraphicsPresetTableData](../../sora1/tbl/schema/GraphicsPresetTableData.py) |
| `t_help.tbl` | [HelpTitle](../../sora1/tbl/schema/HelpTitle.py), [HelpPage](../../sora1/tbl/schema/HelpPage.py), [HelpIconList](../../sora1/tbl/schema/HelpIconList.py), [HelpController](../../sora1/tbl/schema/HelpController.py), [HelpOverlayIcon](../../sora1/tbl/schema/HelpOverlayIcon.py), [RealTimeHelpTableData](../../sora1/tbl/schema/RealTimeHelpTableData.py) |
| `t_item.tbl` | [ItemTableData](schema/ItemTableData.py), [ItemKindParam2](../../sora1/tbl/schema/ItemKindParam2.py), [ItemTabType](../../sora1/tbl/schema/ItemTabType.py), [ItemShopTabType](../../sora1/tbl/schema/ItemShopTabType.py) |
| `t_itemhelp.tbl` | [ConditionHelpData](../../sora1/tbl/schema/ConditionHelpData.py), [SkillEffectTypeHelpData](../../sora1/tbl/schema/SkillEffectTypeHelpData.py), [SkillEffectHelpData](../../sora1/tbl/schema/SkillEffectHelpData.py), [AttrTypeHelpData](../../sora1/tbl/schema/AttrTypeHelpData.py), [SkillTypeHelpData](../../sora1/tbl/schema/SkillTypeHelpData.py), [SkillRangeHelpData](../../sora1/tbl/schema/SkillRangeHelpData.py), [ItemKindHelpData](../../sora1/tbl/schema/ItemKindHelpData.py), [SkillItemStatusData](../../sora1/tbl/schema/SkillItemStatusData.py), [SkillConnectListData](../../sora1/tbl/schema/SkillConnectListData.py), [SkillTextArrayData](../../sora1/tbl/schema/SkillTextArrayData.py), [SkillRangeData](../../sora1/tbl/schema/SkillRangeData.py) |
| `t_lookpoint.tbl` | [LookPointTableData](../../sora1/tbl/schema/LookPointTableData.py) |
| `t_mapjump.tbl` | [MapJumpAreaData](../../sora1/tbl/schema/MapJumpAreaData.py), [MapJumpSpotData](../../sora1/tbl/schema/MapJumpSpotData.py), [MapJumpChrIcon](schema/MapJumpChrIcon.py) |
| `t_marker.tbl` | [MarkerTableData](../../sora1/tbl/schema/MarkerTableData.py) |
| `t_minigame_blackjack.tbl` | [BlackJackMessage](schema/BlackJackMessage.py), [BlackJackInfo](schema/BlackJackInfo.py), [BlackJackHelp](../../sora1/tbl/schema/BlackJackHelp.py), [BlackJackProb](../../sora1/tbl/schema/BlackJackProb.py), [BlackJackRollRate](schema/BlackJackRollRate.py), [BlackJackRuleText](schema/BlackJackRuleText.py) |
| `t_minigame_card_battler.tbl` | [CardData](../../sora1/tbl/schema/CardData.py), [CardEffectText](../../sora1/tbl/schema/CardEffectText.py), [CardAttributeData](../../sora1/tbl/schema/CardAttributeData.py), [AITypeList](../../sora1/tbl/schema/AITypeList.py), [CardBattlerMessage](../../sora1/tbl/schema/CardBattlerMessage.py), [ScoreCoefficient](../../sora1/tbl/schema/ScoreCoefficient.py), [LogText](../../sora1/tbl/schema/LogText.py) |
| `t_minigame_fishing.tbl` | [FishInfo](schema/FishInfo.py), [FishingConstant](schema/FishingConstant.py), [FishingBaitInfo](schema/FishingBaitInfo.py), [FishingRodInfo](schema/FishingRodInfo.py), [FishingCastInfo](../../sora1/tbl/schema/FishingCastInfo.py), [OutItemList](schema/OutItemList.py), [FishingSpot](schema/FishingSpot.py) |
| `t_minigame_poker.tbl` | [PokerMessage](schema/PokerMessage.py), [PokerInfo](schema/PokerInfo.py), [PokerHelp](../../sora1/tbl/schema/PokerHelp.py), [PokerRollRate](schema/PokerRollRate.py), [PokerRuleText](schema/PokerRuleText.py) |
| `t_minigame_roulette.tbl` | [RouletteMessage](schema/RouletteMessage.py), [RouletteInfo](schema/RouletteInfo.py), [RouletteBetRate](schema/RouletteBetRate.py), [RouletteCheat](schema/RouletteCheat.py), [RouletteBetExplain](schema/RouletteBetExplain.py), [RouletteRuleText](schema/RouletteRuleText.py), [RouletteNumber](schema/RouletteNumber.py) |
| `t_minigame_slot.tbl` | [SlotReelPattern](schema/SlotReelPattern.py), [SlotReelSpeed](schema/SlotReelSpeed.py), [SlotInfo](schema/SlotInfo.py), [SlotRoles](schema/SlotRoles.py), [SlotBonus](schema/SlotBonus.py), [SlotCheat](schema/SlotCheat.py), [SlotEvent](schema/SlotEvent.py), [SlotTBoxEvent](schema/SlotTBoxEvent.py), [SlotBattleEvent](schema/SlotBattleEvent.py), [SlotPomInfo](schema/SlotPomInfo.py), [SlotMonsterInfo](schema/SlotMonsterInfo.py), [SlotTBoxInfo](schema/SlotTBoxInfo.py) |
| `t_mon_a*.tbl` | [MonsterSettingParam](schema/MonsterSettingParam.py) |
| `t_mon_a1000.tbl` | [MonsterSettingParamA8](schema/MonsterSettingParam.py) |
| `t_mon_a1005.tbl` | [MonsterSettingParamA8](schema/MonsterSettingParam.py) |
| `t_mon_mp*.tbl` | [MonsterSettingParam](schema/MonsterSettingParam.py) |
| `t_name.tbl` | [NameTableData](../../sora1/tbl/schema/NameTableData.py) |
| `t_notemenu.tbl` | [NoteMainCategory](../../sora1/tbl/schema/NoteMainCategory.py), [NoteMainBadge](../../sora1/tbl/schema/NoteMainBadge.py), [NoteMainPartnerInfo](schema/NoteMainPartnerInfo.py), [NoteMainAffiliation](../../sora1/tbl/schema/NoteMainAffiliation.py), [NoteMainHistory8](schema/NoteMainHistory.py), [NoteBattleCategory](../../sora1/tbl/schema/NoteBattleCategory.py), [NoteCookCategory](../../sora1/tbl/schema/NoteCookCategory.py), [NoteHelpCategory](../../sora1/tbl/schema/NoteHelpCategory.py), [NoteFishingCategory](schema/NoteFishingCategory.py), [NoteMonsRecordData](schema/NoteMonsRecordData.py), [NoteCookChara](schema/NoteCookChara.py), [NoteCookItem](../../sora1/tbl/schema/NoteCookItem.py), [NoteCookRecipe](../../sora1/tbl/schema/NoteCookRecipe.py), [NoteCookBonusChara](../../sora1/tbl/schema/NoteCookBonusChara.py) |
| `t_npc_1071_01.tbl` | [NPCParam](../../sora1/tbl/schema/NPCParam.py) |
| `t_npc_a*.tbl` | [NPCParam](../../sora1/tbl/schema/NPCParam.py) |
| `t_npc_c0000.tbl` | [NPCParam98](../../sora1/tbl/schema/NPCParam.py) |
| `t_npc_mp*.tbl` | [NPCParam](../../sora1/tbl/schema/NPCParam.py) |
| `t_orbment.tbl` | [OrbmentSlotParam](schema/OrbmentSlotParam.py), [QuartzParam](../../sora1/tbl/schema/QuartzParam.py), [ArtsParam](../../sora1/tbl/schema/ArtsParam.py), [AttrData](../../sora1/tbl/schema/AttrData.py) |
| `t_place.tbl` | [PlaceTableData](../../sora1/tbl/schema/PlaceTableData.py) |
| `t_popup_face.tbl` | [PopupFaceParam](../../sora1/tbl/schema/PopupFaceParam.py) |
| `t_quest.tbl` | [QuestRank](../../sora1/tbl/schema/QuestRank.py), [QuestRankBefore](schema/QuestRankBefore.py), [QuestChapterRank](../../sora1/tbl/schema/QuestChapterRank.py), [QuestTitle](../../sora1/tbl/schema/QuestTitle.py), [QuestText38](schema/QuestText.py), [NaviText](schema/NaviText.py), [QuestReportVoice](../../sora1/tbl/schema/QuestReportVoice.py) |
| `t_quest_fc.tbl` | [QuestRank](../../sora1/tbl/schema/QuestRank.py), [QuestTitle](../../sora1/tbl/schema/QuestTitle.py), [QuestText](../../sora1/tbl/schema/QuestText.py), [NoteMainCategory](../../sora1/tbl/schema/NoteMainCategory.py), [NoteMainBadge](../../sora1/tbl/schema/NoteMainBadge.py), [NoteMainAffiliation](../../sora1/tbl/schema/NoteMainAffiliation.py), [NoteMainHistory](../../sora1/tbl/schema/NoteMainHistory.py) |
| `t_scene_setting.tbl` | [SceneCommonSetting](../../sora1/tbl/schema/SceneCommonSetting.py), [SceneSkySetting](../../sora1/tbl/schema/SceneSkySetting.py) |
| `t_se.tbl` | [SETableData](../../sora1/tbl/schema/SETableData.py) |
| `t_shop.tbl` | [ShopInfo](../../sora1/tbl/schema/ShopInfo.py), [ShopItem](../../sora1/tbl/schema/ShopItem.py), [ShopTypeDesc](../../sora1/tbl/schema/ShopTypeDesc.py), [ShopConv](../../sora1/tbl/schema/ShopConv.py), [TradeItem](../../sora1/tbl/schema/TradeItem.py), [MedalItem](schema/MedalItem.py), [CharaSettingInfo](../../sora1/tbl/schema/CharaSettingInfo.py), [CharaArrange](schema/CharaArrange.py) |
| `t_skill.tbl` | [SkillParam](../../sora1/tbl/schema/SkillParam.py), [SkillPowerIcon](../../sora1/tbl/schema/SkillPowerIcon.py), [SkillGetParam](schema/SkillGetParam.py) |
| `t_status.tbl` | [StatusParam](schema/StatusParam.py) |
| `t_support_ability.tbl` | [SupportAbilityParam](../../sora1/tbl/schema/SupportAbilityParam.py), [SupportLevelData](../../sora1/tbl/schema/SupportLevelData.py) |
| `t_talk.tbl` | [TalkTableData](schema/TalkTableData.py) |
| `t_tbox.tbl` | [TBoxParam](schema/TBoxParam.py) |
| `t_text.tbl` | [TextTableData](../../sora1/tbl/schema/TextTableData.py) |
| `t_tips.tbl` | [TipsTableData](../../sora1/tbl/schema/TipsTableData.py) |
| `t_title.tbl` | [TitleTableData](../../sora1/tbl/schema/TitleTableData.py) |
| `t_uds.tbl` | [UDSActivityData](../../sora1/tbl/schema/UDSActivityData.py) |
| `t_viewer.tbl` | [ViewerMainList](schema/ViewerMainList.py), [ViewerSystemList](schema/ViewerSystemList.py), [ViewerMapList](schema/ViewerMapList.py), [ViewerCharaSelectList](schema/ViewerCharaSelectList.py), [ViewerCharaEquipList](schema/ViewerCharaEquipList.py), [ViewerShotList](schema/ViewerShotList.py), [ViewerMapData](schema/ViewerMapData.py), [ViewerEnvList](schema/ViewerEnvList.py), [ViewerBGMList](schema/ViewerBGMList.py), [ViewerCharaList](schema/ViewerCharaList.py), [ViewerCostumeList](schema/ViewerCostumeList.py), [ViewerAttachList](schema/ViewerAttachList.py), [ViewerHairList](schema/ViewerHairList.py), [ViewerWeaponList](schema/ViewerWeaponList.py), [ViewerFaceList](schema/ViewerFaceList.py), [ViewerMouseList](schema/ViewerMouseList.py), [ViewerCheekList](schema/ViewerCheekList.py), [ViewerEyeLineList](schema/ViewerEyeLineList.py), [ViewerNeckDirList](schema/ViewerNeckDirList.py), [ViewerMotionList](schema/ViewerMotionList.py) |
| `t_voice.tbl` | [VoiceTableData](../../sora1/tbl/schema/VoiceTableData.py) |
