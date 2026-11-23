# sora1 tables

Each table in `sora1/extracted/table_en/` and the schema classes that read it, in the order of its sections. Every
class is in this folder's `schema/`. A pattern row, such as `t_mon_a*.tbl`, covers the files of that name that have
no row of their own. More on the classes: [TBL_FORMAT.md](../../../../../docs/falcom/ed9/TBL_FORMAT.md),
"Record Classes".

| Table | Schemas |
|---|---|
| `t_achievement.tbl` | [AchievementTableData](schema/AchievementTableData.py), [AchievementCategoryData](schema/AchievementCategoryData.py), [PlayRecordData](schema/PlayRecordData.py) |
| `t_active_voice.tbl` | [ActiveVoiceTableData](schema/ActiveVoiceTableData.py) |
| `t_ani_param.tbl` | [AniParam](schema/AniParam.py) |
| `t_bgm.tbl` | [BGMTableData](schema/BGMTableData.py) |
| `t_bgmset.tbl` | [MapBGM](schema/MapBGM.py), [BattleBGM](schema/BattleBGM.py) |
| `t_books.tbl` | [BooksTitle](schema/BooksTitle.py), [BooksText](schema/BooksText.py), [BooksCategory](schema/BooksCategory.py) |
| `t_break_object.tbl` | [BreakObjectTableData](schema/BreakObjectTableData.py), [WeedingTableData](schema/WeedingTableData.py) |
| `t_btl_result_voice.tbl` | `BTResultTable`: no schema, read as raw hex |
| `t_btl_voice.tbl` | [BTLVoiceTable](schema/BTLVoiceTable.py) |
| `t_btlsys.tbl` | [ATBonusParam](schema/ATBonusParam.py), [ATBonusSet](schema/ATBonusSet.py), [BattleLevelField](schema/BattleLevelField.py), [BattleLevelTurn](schema/BattleLevelTurn.py), [BattleEnemyLevelStatusAdjust](schema/BattleEnemyLevelStatusAdjust.py), [BattleEnemyDamageAdjust](schema/BattleEnemyDamageAdjust.py), [BattleEnemyLevelAdjust](schema/BattleEnemyLevelAdjust.py), [BattleSCraftDamageRatio](schema/BattleSCraftDamageRatio.py), [TacticalBonus](schema/TacticalBonus.py) |
| `t_chapter.tbl` | [ChapterParam](schema/ChapterParam.py) |
| `t_chrdata.tbl` | [ChrDataParam](schema/ChrDataParam.py), [TalkChrData](schema/TalkChrData.py), [PortraitDataParam](schema/PortraitDataParam.py) |
| `t_collision_info.tbl` | [CollisionFootStepInfo](schema/CollisionFootStepInfo.py) |
| `t_condition_info.tbl` | [ConditionInfoTableData](schema/ConditionInfoTableData.py), [ConditionTypeParam](schema/ConditionTypeParam.py), [OverDriveEffect](schema/OverDriveEffect.py) |
| `t_constant_value.tbl` | [ConstantValue](schema/ConstantValue.py) |
| `t_costume.tbl` | [CostumeParam](schema/CostumeParam.py), [CostumeAttachOffset](schema/CostumeAttachOffset.py) |
| `t_dlc.tbl` | [DLCTableData](schema/DLCTableData.py) |
| `t_dlc_appid_convert.tbl` | [DLCAppIDConvertTableData](schema/DLCAppIDConvertTableData.py) |
| `t_effect.tbl` | [EffectTableData](schema/EffectTableData.py) |
| `t_eventbox.tbl` | [EventBoxTableData](schema/EventBoxTableData.py) |
| `t_evtable.tbl` | [EventGroupData](schema/EventGroupData.py), [EventSubGroupData](schema/EventSubGroupData.py), [EventTableData](schema/EventTableData.py) |
| `t_face_anime.tbl` | [FaceAnimeData](schema/FaceAnimeData.py), [EyePresetData](schema/EyePresetData.py), [EyeScaleData](schema/EyeScaleData.py), [MouthPatternMap](schema/MouthPatternMap.py), [EyeAttachData](schema/EyeAttachData.py), [EyeModifyAttachData](schema/EyeModifyAttachData.py), [EyeDirPatternNameData](schema/EyeDirPatternNameData.py), [EyeLidsPatternNameData](schema/EyeLidsPatternNameData.py), [EyeBrowsPatternNameData](schema/EyeBrowsPatternNameData.py), [EyeModifyPatternNameData](schema/EyeModifyPatternNameData.py), [MouthPatternNameData](schema/MouthPatternNameData.py), [EyeBallSizePatternNameData](schema/EyeBallSizePatternNameData.py), [FaceTexturePatternNameData](schema/FaceTexturePatternNameData.py) |
| `t_field_item.tbl` | [FieldItemTableData](schema/FieldItemTableData.py) |
| `t_graphics_preset.tbl` | [GraphicsPresetTableData](schema/GraphicsPresetTableData.py) |
| `t_help.tbl` | [HelpTitle](schema/HelpTitle.py), [HelpPage](schema/HelpPage.py), [HelpIconList](schema/HelpIconList.py), [HelpController](schema/HelpController.py), [HelpOverlayIcon](schema/HelpOverlayIcon.py), [RealTimeHelpTableData](schema/RealTimeHelpTableData.py) |
| `t_item.tbl` | [ItemTableData](schema/ItemTableData.py), [ItemKindParam2](schema/ItemKindParam2.py), [ItemTabType](schema/ItemTabType.py), [ItemShopTabType](schema/ItemShopTabType.py) |
| `t_itemhelp.tbl` | [ConditionHelpData](schema/ConditionHelpData.py), [SkillEffectTypeHelpData](schema/SkillEffectTypeHelpData.py), [SkillEffectHelpData](schema/SkillEffectHelpData.py), [AttrTypeHelpData](schema/AttrTypeHelpData.py), [SkillTypeHelpData](schema/SkillTypeHelpData.py), [SkillRangeHelpData](schema/SkillRangeHelpData.py), [ItemKindHelpData](schema/ItemKindHelpData.py), [SkillItemStatusData](schema/SkillItemStatusData.py), [SkillConnectListData](schema/SkillConnectListData.py), [SkillTextArrayData](schema/SkillTextArrayData.py), [SkillRangeData](schema/SkillRangeData.py) |
| `t_lookpoint.tbl` | [LookPointTableData](schema/LookPointTableData.py) |
| `t_mapjump.tbl` | [MapJumpAreaData](schema/MapJumpAreaData.py), [MapJumpSpotData](schema/MapJumpSpotData.py) |
| `t_marker.tbl` | [MarkerTableData](schema/MarkerTableData.py) |
| `t_minigame_blackjack.tbl` | [BlackJackMessage](schema/BlackJackMessage.py), [BlackJackMedal](schema/BlackJackMedal.py), [BlackJackHelp](schema/BlackJackHelp.py), [BlackJackProb](schema/BlackJackProb.py) |
| `t_minigame_card_battler.tbl` | [CardData](schema/CardData.py), [CardEffectText](schema/CardEffectText.py), [CardAttributeData](schema/CardAttributeData.py), [AITypeList](schema/AITypeList.py), [CardBattlerMessage](schema/CardBattlerMessage.py), [ScoreCoefficient](schema/ScoreCoefficient.py), [LogText](schema/LogText.py) |
| `t_minigame_fishing.tbl` | [FishInfo](schema/FishInfo.py), [FishingConstant](schema/FishingConstant.py), `FishingBaitInfo`: empty, no schema, [FishingCastInfo](schema/FishingCastInfo.py), [FishingSpot](schema/FishingSpot.py) |
| `t_minigame_poker.tbl` | [PokerMessage](schema/PokerMessage.py), [PokerMedal](schema/PokerMedal.py), [PokerHelp](schema/PokerHelp.py), [PokerTrickLevel](schema/PokerTrickLevel.py) |
| `t_mon_a*.tbl` | [MonsterSettingParam](schema/MonsterSettingParam.py) |
| `t_mon_mp*.tbl` | [MonsterSettingParam](schema/MonsterSettingParam.py) |
| `t_name.tbl` | [NameTableData](schema/NameTableData.py) |
| `t_notemenu.tbl` | [NoteMainCategory](schema/NoteMainCategory.py), [NoteMainBadge](schema/NoteMainBadge.py), [NoteMainAffiliation](schema/NoteMainAffiliation.py), [NoteMainHistory](schema/NoteMainHistory.py), [NoteBattleCategory](schema/NoteBattleCategory.py), [NoteCookCategory](schema/NoteCookCategory.py), [NoteHelpCategory](schema/NoteHelpCategory.py), [NoteMonsRecordData](schema/NoteMonsRecordData.py), [NoteCookChara](schema/NoteCookChara.py), [NoteCookItem](schema/NoteCookItem.py), [NoteCookRecipe](schema/NoteCookRecipe.py), [NoteCookBonusChara](schema/NoteCookBonusChara.py) |
| `t_npc_1071_01.tbl` | [NPCParam](schema/NPCParam.py) |
| `t_npc_a1000.tbl` | [NPCParam](schema/NPCParam.py) |
| `t_npc_a9100.tbl` | [NPCParam](schema/NPCParam.py) |
| `t_npc_c0000.tbl` | [NPCParam98](schema/NPCParam.py) |
| `t_npc_mp*.tbl` | [NPCParam](schema/NPCParam.py) |
| `t_orbment.tbl` | [OrbmentSlotParam](schema/OrbmentSlotParam.py), [QuartzParam](schema/QuartzParam.py), [ArtsParam](schema/ArtsParam.py), [AttrData](schema/AttrData.py) |
| `t_place.tbl` | [PlaceTableData](schema/PlaceTableData.py) |
| `t_popup_face.tbl` | [PopupFaceParam](schema/PopupFaceParam.py) |
| `t_quest.tbl` | [QuestRank](schema/QuestRank.py), [QuestChapterRank](schema/QuestChapterRank.py), [QuestTitle](schema/QuestTitle.py), [QuestText](schema/QuestText.py), [NaviText](schema/NaviText.py), [QuestReportVoice](schema/QuestReportVoice.py) |
| `t_scene_setting.tbl` | [SceneCommonSetting](schema/SceneCommonSetting.py), [SceneSkySetting](schema/SceneSkySetting.py) |
| `t_se.tbl` | [SETableData](schema/SETableData.py) |
| `t_shop.tbl` | [ShopInfo](schema/ShopInfo.py), [ShopItem](schema/ShopItem.py), [ShopTypeDesc](schema/ShopTypeDesc.py), [ShopConv](schema/ShopConv.py), [TradeItem](schema/TradeItem.py), [CharaSettingInfo](schema/CharaSettingInfo.py), [CharaArrange](schema/CharaArrange.py) |
| `t_skill.tbl` | [SkillParam](schema/SkillParam.py), [SkillPowerIcon](schema/SkillPowerIcon.py), `SkillGetParam`: empty, no schema |
| `t_status.tbl` | [StatusParam](schema/StatusParam.py) |
| `t_support_ability.tbl` | [SupportAbilityParam](schema/SupportAbilityParam.py), [SupportLevelData](schema/SupportLevelData.py) |
| `t_tbox.tbl` | [TBoxParam](schema/TBoxParam.py) |
| `t_text.tbl` | [TextTableData](schema/TextTableData.py) |
| `t_tips.tbl` | [TipsTableData](schema/TipsTableData.py) |
| `t_title.tbl` | [TitleTableData](schema/TitleTableData.py) |
| `t_uds.tbl` | [UDSActivityData](schema/UDSActivityData.py) |
| `t_voice.tbl` | [VoiceTableData](schema/VoiceTableData.py) |
