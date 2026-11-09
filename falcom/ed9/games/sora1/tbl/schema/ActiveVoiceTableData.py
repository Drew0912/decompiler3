from falcom.ed9.parser.tbl import TableDataEntry


# t_active_voice.tbl
class ActiveVoiceTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',          'I'),   # 0: none; rows of one ID play in order
        ('group',       'B'),
        ('pad05',       'P3'),
        ('chrIds',      'A2'),
        ('uint32_14',   'I'),
        ('speaker',     'S'),
        ('kind',        'W'),   # 0: plays once only; 1: a battle talk sound
        ('pad22',       'P6'),
        # flags, a bit per letter:
        #   F 0x2: no 2D image of the speaker is built, and a wait on the voice slot is skipped
        #   D 0x8: flagsOnPlay is set after the last row of this ID has played, not when the line is queued
        #   C 0x10: the voice isn't attached to the speaker's character in the game world; it still plays
        #   P 0x20: goes into voice slot 0 if free; if not, slot 0's line gets the mark that apparently ends a line
        #     (the one Q sets), the other lines move up one slot, and this one takes slot 1
        #   S 0x100: the check on the speakers also covers party slots 4 and up
        #   L 0x200: not used when its first speaker is the party member in a party slot the voice code remembers
        #     (which slot, so who: not known)
        #   R 0x400: needs a speaker equal to the character the voice code remembers or, if none, to the party member
        #     in the party slot it remembers (as in L); group never skips a row with R
        #   N 0x800: every speaker must be in the party
        #   T 0x1000: one speaker is picked at random, and the other speakers' rows are dropped
        #   Q 0x2000: may start while other lines are playing (without Q, all 16 voice slots must be free); a new
        #     line apparently stops each queued line of kind 2 or more that lacks Q
        #   K 0x4000: M's and E's check on the speakers uses only this row's speakers, not those of all the ID's rows
        #   A 0x8000: when voiceIds and chrIds have the same count (so they pair up by position), each voice plays
        #     only if its character exists
        #   M 0x40, E 0x80: on a row of kind 1, an unknown check is made on the speakers
        #   W 0x1: read by code, purpose not known
        ('flags',       'S'),
        ('flagsSet',    'A2'),  # plays only if all of these scenario flags are set; a 0 is skipped
        ('uint32_3c',   'I'),
        ('flagsClear',  'A2'),  # plays only if none of these scenario flags are set
        ('uint32_4c',   'I'),
        ('flagsOnPlay', 'A2'),  # won't play if all are already set; then set at the start, or at the end if flags has D
        ('uint32_5c',   'I'),
        ('voiceIds',    'A4'),  # paired with chrIds by position when both have the same count
        ('uint32_6c',   'I'),
        ('text',        'S'),
        ('float32_78',  'f'),
        ('uint32_7c',   'I'),
    )
