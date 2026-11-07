from falcom.ed9.parser.tbl import TableDataEntry


# t_quest.tbl
class QuestReportVoice(TableDataEntry):
    DESCRIPTOR = (
        ('key',       'W'),
        ('pad02',     'P6'),
        ('listKind0', 'A4'),
        ('uint32_14', 'I'),
        ('listKind1', 'A4'),
        ('uint32_24', 'I'),
        ('listKind2', 'A4'),
        ('uint32_34', 'I'),
        ('listKind3', 'A4'),
        ('uint32_44', 'I'),
        ('listKind4', 'A4'),
        ('uint32_54', 'I'),
    )
