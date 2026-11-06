# ED9 Table Format (`.tbl`)

> Status: current for `sora1` and `sora2`; the other games on this format are not checked. How a `.tbl` game table is
> laid out, how `falcom/ed9/parser/tbl.py` reads one, and how to add a table. Read-only: nothing rebuilds a `.tbl` yet.

## File Layout

Little-endian throughout, in this order:

| Part | Size | Content |
|---|---|---|
| Header | 8 | Magic `#TBL`, then the section count (4 bytes) |
| Section entries | `0x50` each | One per section |
| Records | Each section's size x count | The sections' records, in entry order, back to back |
| Data block | To end of file | The strings and arrays the records point to; absent in a file with neither |

A section entry:

| Offset | Size | Field |
|---|---|---|
| `0x00` | 64 | Name, ASCII, NUL-padded |
| `0x40` | 4 | Name hash: `~crc32(name)`, as `hash_function_name` in `falcom/ed9/structs/crc32.py`; the reader ignores it |
| `0x44` | 4 | Offset of the section's first record, from the start of the file |
| `0x48` | 4 | Record size in bytes |
| `0x4c` | 4 | Record count, which may be 0 |

A file holds one or more sections (`t_item.tbl` has four, with different record sizes), so a layout belongs to a
section, not to a file. Most files hold one.

## Records and the Data Block

A record has a fixed size, and its fields have no tags: only a schema says where one ends.

- **A string** is an 8-byte pointer, an offset from the start of the file, to UTF-8 text ending in a NUL.
- **An array** is 12 bytes: an 8-byte pointer, then a 4-byte element count. Its elements are in the data block, with no
  type stored anywhere. An unused 4 bytes usually follows, making 16.
- **Two fields may share 8 bytes:** `NPCParam` `+0x00` holds two 2-byte IDs. A value that reads as one large number may
  be two small ones.

The data block has no header. In `t_name.tbl` its strings follow the order of the record fields that point to them.
Rules a reader needs:

- A string item is its text and NUL. Identical pointers share one item (`t_bgmset.tbl`); in `t_name.tbl` nothing is
  shared, and even an empty string has its own NUL.
- An array aligns to its element size, so up to 3 zero bytes of padding can come before it.
- **An empty array still aligns the block and keeps a pointer.** So padding can appear before a string, and an empty
  array's pointer can equal the next item's, which makes it look like a string pointer.
- A string pointer equal to the file size is an empty string (`t_bgmset.tbl`).

## Reading a Table

`python falcom/ed9/games/<game>/tbl2py.py <file or folder> [-o <folder>]` writes each table as a Python file, by default
to the game's `out/tables/`:

```python
from falcom.ed9.games.sora2.tbl.tbl_records import *


entries = [
    NameTableData(
        chrId   = 0x0000,
        chrName = 'Estelle',
        ...
    ),
]
```

Another script imports `entries` when it needs the data. `TblParser` reads each section through the class of its name
and record size. A section with no such class stays raw hex (`RawTableEntry`), one entry per record. `problems` holds
whatever did not fit, and the launcher logs each as a warning.

## Record Classes

A game's classes are in `falcom/ed9/games/<game>/tbl/tbl_records.py`. A class's `DESCRIPTOR` lists its fields in record
order; each kind is a letter or two, defined in `FIELD_KINDS` (`parser/tbl.py`), with a key at the top of every
`tbl_records.py`. A new kind updates each key.

`sora2`'s file star-imports `sora1`'s and defines what differs, since the two are remakes in one series; a class of the
same name replaces `sora1`'s. `kuro1`, `kuro2` and `kai1` are a separate group: they do not build on these files.

Adding a table:

1. Find the section's name and record size in the file's header.
2. Write the class in the earliest game of the group that has it. Name it for the section. A second size of one section
   gets its own class with `SECTION` set and its size as a suffix (`NPCParam98`), since the name alone cannot pick it.
3. Name a field only where the data shows what it is; name the rest by offset (`str08`, `int44`).
4. Run `tbl2py.py` on the table in every game of the group, and fix anything in `problems`.
5. Where a later game's layout differs, define the class in that game's file. A size can match and the layout still
   differ: `MonsterSettingParam` `0xa8` is one layout in `sora1` and another in `sora2`.

## What the Checks Prove

| Check | Catches | Does not catch |
|---|---|---|
| Name and record size | A size no class has: reported if the name has a class at another size | A changed layout of the same size |
| String and array pointers | A pointer outside the data block, an unaligned array, text that is not UTF-8: reported, and the section stays raw | A number misread as a pointer that lands on valid text; the next check usually does |
| Data block accounting | A gap or overlap: every byte must belong to one item, or be padding before one | Anything when a section of the file is raw, since its pointers are unknown |

So a table with no problems has the right record size and the right pointer fields. The checks say nothing about the
rest: two 2-byte fields read as one 4-byte field, or an integer read as a float of the same width, give no error, and a
field's name is only a reading of its values. A wrong type gives a wrong value in `entries`, not a wrong file.

## Character IDs

`NameTableData` (`t_name.tbl`) lists characters and their costumes. What is known about its IDs:

- `chrId` looks like the ID scripts pass to `chr_*` calls: `chr_create` agrees with the table's model on most calls. Not
  proved.
- `0xFFFF` marks a row with no ID of its own, mostly costumes.
- An ID may repeat, and a name repeats often (`Estelle` has three IDs), so a name is not a key.
- Scripts use IDs that are not in the table: scene-local ones such as `20851`, and pseudo IDs such as `65534`.

## Games on This Format

| Game | Tables | Section names | Layouts (name and size) |
|---|---|---|---|
| `sora1` | 237 | 151 | 152 |
| `sora2` | 315 | 203 | 207 |

The two share 132 layouts by name and size, most of `sora1`'s; equal size does not prove equal fields. `sora2` adds
tables such as `TalkTableData` and the `Viewer*` family, and changes others (`ItemTableData` `0xe8` to `0x100`). The
container fits every table of both games. `kuro1`, `kuro2` and `kai1` have tables too (`table_en/`, `kai1`:
`table_eng/`), not read.
