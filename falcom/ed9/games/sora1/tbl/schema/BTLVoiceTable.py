from falcom.ed9.parser.tbl import TableDataEntry


# t_btl_voice.tbl
class BTLVoiceTable(TableDataEntry):
    DESCRIPTOR = (
        ('key',        'I'),
        ('key2',       'I'),   # 0xFFFF: matches any value
        ('uint32_08',  'I'),
        ('filterKey',  'I'),
        ('flagsSet',   'A2'),  # scenario flags that must all be set; a 0 fails unless every entry is 0
        ('uint32_1c',  'I'),
        ('flagsClear', 'A2'),  # scenario flags none of which may be set; a 0 is skipped
        ('uint32_2c',  'I'),
        ('voiceIds',   'A4'),  # one is picked at random, skipping one equal to the caller's value (0, or its last pick)
        ('uint32_3c',  'I'),
        ('function',   'S'),   # a script function; a non-zero result replaces the pick
        ('weights',    'A1'),  # the exe reads one per voiceIds entry; this count only switches them on
        ('uint32_54',  'I'),
    )
