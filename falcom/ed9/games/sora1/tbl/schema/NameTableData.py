from falcom.ed9.parser.tbl import TableDataEntry


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
        # flags, a bit per letter:
        #   I 0x2: apparently left out of menus that list characters, such as the character-select screen
        #   L 0x4: left out of the battle result dialog
        #   F 0x1, A 0x8, S 0x10: read by code, purpose not known
        #   D: a letter that sets no bit (the loader has no case for it)
        ('flags',            'S'),
        ('saveIndex',        'B'),   # 1 to 0x63; 0: none
        ('pad39',            'P7'),
        ('statusKey',        'S'),
        ('scenarioFlag',     'W'),   # 0: none
        ('pad4a',            'P6'),
        ('flaggedStatusKey', 'S'),
        ('str58',            'S'),
        ('str60',            'S'),
    )
