from falcom.ed9.parser.tbl import TableDataEntry


# t_itemhelp.tbl
class SkillItemStatusData(TableDataEntry):
    DESCRIPTOR = (
        # a row per item stat (sora2's ItemTableData): key 0 maxHp, 1 maxEp, 6 to 9 str, def_, ats, adf,
        # 0xA acc, 0xB eva, 0xC aev, 0xD crt, 0xE spd, 0xF mov; key + 0x10 for a negative value (crt's:
        # 0x27); no lookup found for 2 to 5
        ('id',          'W'),
        ('pad02',       'P6'),
        ('text',        'S'),   # maxHp, maxEp: appended to the help text so far, which is then formatted with the value
        ('name',        'S'),   # the other stats: put after prefix
        ('valueFormat', 'S'),   # the other stats: formatted with the value, after the names of stats of equal value
        ('uint64_20',   'Q'),
        ('prefix',      'S'),   # put before text or name
    )
