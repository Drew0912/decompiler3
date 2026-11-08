from falcom.ed9.parser.tbl import TableDataEntry


# t_face_anime.tbl
class EyeModifyAttachData(TableDataEntry):
    DESCRIPTOR = (
        ('pattern',   'B'),
        ('selector',  'B'),
        ('objectId',  'w'),   # -1: none; created if the owner has no object with this ID
        ('pad04',     'P4'),
        ('arr16_08',  'A2'),
        ('uint32_14', 'I'),
        ('function',  'S'),   # a script function, called with objectId
    )
