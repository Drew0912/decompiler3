"""sora1's .tbl record classes, the base of sora2's: falcom/ed9/parser/tbl.py reads a section through them"""

from falcom.ed9.parser.tbl import RawTableEntry, TableDataEntry    # RawTableEntry: for generated files' star import


# t_name.tbl
class NameTableData(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',   'X'),
        ('chrName', 'S'),
        ('model',   'S'),
        ('face',    'S'),
        ('ani',     'S'),
        ('num28',   'Q'),
        ('str30',   'S'),
        ('num38',   'Q'),
        ('str40',   'S'),
        ('num48',   'Q'),
        ('str50',   'S'),
        ('str58',   'S'),
        ('str60',   'S'),
    )
