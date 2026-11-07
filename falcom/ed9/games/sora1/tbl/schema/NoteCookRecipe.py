from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteCookRecipe(TableDataEntry):
    DESCRIPTOR = (
        ('itemId',  'I'),
        ('item1',   'I'),
        ('amount1', 'B'),
        ('pad09',   'P3'),
        ('item2',   'I'),
        ('amount2', 'B'),
        ('pad11',   'P3'),
        ('item3',   'I'),
        ('amount3', 'B'),
        ('pad19',   'P3'),
        ('item4',   'I'),
        ('amount4', 'B'),
        ('pad21',   'P3'),
        ('item5',   'I'),
        ('amount5', 'B'),
        ('pad29',   'P3'),
        ('item6',   'I'),
        ('amount6', 'B'),
        ('pad31',   'P3'),
        ('item7',   'I'),
        ('amount7', 'B'),
        ('pad39',   'P3'),
        ('item8',   'I'),
        ('amount8', 'B'),
        ('pad41',   'P3'),
    )
