from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerMotionList(TableDataEntry):
    DESCRIPTOR = (
        ('id',     'I'),
        ('pad04',  'P4'),
        ('name',   'S'),
        ('str10',  'S'),
        # flags, a bit per letter:
        #   A 0x1 Weapon, O 0x2 OrbmentAria, C 0x4 Cocktail, G 0x8 Glass, T 0x10 Cup, M 0x20 Mug: each bit set
        #     plays the clip AniAttach + that name (AniAttachWeapon ...); a bit clear plays AniDetach + the name
        #     instead; only for characters whose flags2 have H
        #   S 0x40: AniSitWait in place of AniWait
        #   D 0x100: when the motion runs out, it replays without going through the wait clip
        #   L 0x80: nothing found reading it
        ('flags',  'S'),
        # flags2, a bit per letter:
        #   (one letter set, shared with ViewerCharaList flags2)
        #   H 0x1, M 0x2, F 0x4, A 0x8, C 0x10, B 0x20, E 0x40, N 0x80: listed only if the character's flags2 have it
        #   P 0x100: not listed if the chosen costume's flags have P (with no costume chosen: if the character's
        #     flags2 have P)
        #   J 0x800: not listed for a character whose flags2 have J
        #   L 0x200, S 0x1000: nothing found reading it
        ('flags2', 'S'),
    )
