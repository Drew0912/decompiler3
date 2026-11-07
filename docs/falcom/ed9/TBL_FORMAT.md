# ED9 Table Format (`.tbl`)

> Status: current for `sora1` and `sora2`, whose tables all have classes but one; the other games on this format are
> not checked. How a `.tbl` game table is laid out, how `falcom/ed9/parser/tbl.py` reads and rebuilds one, how the game
> reads one, and how to add a table.

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
| `0x40` | 4 | Name hash: `~crc32(name)`, as `hash_function_name` in `falcom/ed9/structs/crc32.py`; the reader ignores it, a rebuild sets it |
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
- **Padding:** a narrow field can be followed by zero bytes up to the next field. A class lists them with a `P` kind
  (`NameTableData` `+0x02`). They are no field of a row: a non-zero byte is reported, and a rebuild writes zeros.

The data block has no header. Its items follow the records in order, and each record's fields in order. Nothing is
shared: two equal strings are two items. Every table of `sora1` and `sora2` is packed this way. The rules:

- A string item is its text and NUL; even an empty string has its own NUL.
- An array aligns to its element size, so up to 3 zero bytes of padding can come before it.
- **An empty array still aligns the block and keeps a pointer.** So padding can appear before a string, and an empty
  array's pointer can equal the next item's, or the file size when nothing follows (`t_bgmset.tbl`), which makes it look
  like a string pointer.

## Reading a Table

`python falcom/ed9/games/<game>/tbl2py.py <file or folder> [-o <folder>]` writes each table as a Python file, by default
to the game's `out/tbl/`:

```python
from falcom.ed9.games.sora2.tbl.schema_all import *


entries = [
    NameTableData(
        chrId   = 0x0000,
        chrName = 'Estelle',
        ...
    ),
]


if __name__ == '__main__':
    # Sections come from entries; a file they cannot describe lists them in order:
    # sections=[(record class, row count), ...]
    create_tbl('t_name.tbl', *entries)
```

Another script imports `entries` when it needs the data. `TblParser` reads each section through the class of its name
and record size. A section with no such class stays raw hex (`RawTableEntry`), one entry per record. `problems` holds
whatever did not fit, and the launcher logs each as a warning. `BTResultTable` has no class on
purpose: a single section with no pointers and no reader in the exe, so nothing could check one.

## Rebuilding a Table

Running a generated script writes its `.tbl` to the current folder: byte for byte the original when unedited, with every
pointer worked out again when edited. Rows can be changed, added or removed. `create_tbl` works out the sections from
`entries`, in the order the rows name them.

When `entries` cannot describe a file, its script lists the sections, as (record class, row count) in file order. That
happens when a section is empty, so no row names it, or when a section name repeats, as in `t_status.tbl`. Editing the
rows of such a script means editing its counts too: counts that do not fit `entries` are an error. A section with no
class is listed as `RawSection(name, record size)`:

```python
create_tbl('t_skill.tbl', *entries, sections=[
    (SkillParam, 218),
    (SkillPowerIcon, 13),
    (RawSection('SkillGetParam', 0xa), 0),
])
```

A row with an unknown or missing field, or a number too big for its field, is an error at that row's line in the script.
A raw row whose hex is not the length of the rows before it is an error too, naming its place in `entries`.

A raw section rebuilds from its hex, so any pointers in it stay as they were. That is right only in a file with no data
block, which holds for every raw section in `sora1` and `sora2`; a later game's raw section in a file with a data block
would rebuild wrong.

## How the Game Reads a Table

From a static read of the `sora2` exe (`sora_2nd.exe` 1.5.0.0), so only the code read so far; no other game's exe is
read.

- **Sections** are found by name in `NameTable` and `MonsterSettingTable`, and by position, as the first entry, in
  `BGMTable`, `TitleTable`, `BtlVoiceTable`, `NPCTable`, `PlaceTable`, `SETable` and `TextTable`. A file read by
  position has one section in `sora2`.
- **Not checked:** the magic, the name hash and the record size. The size is only the step between rows; a field's
  offset is fixed in the code, so a row of another size is misread, not rejected.
- **Pointers** are fixed up once, at load: a non-zero value gets the file's address added, and 0 stays a null pointer.
- **Letter fields:** some strings hold letters that the load turns into flags, in place of the pointer: `flags`, and
  `flags2` where a table has a second, as in `NameTableData`, `ItemTableData` and `StatusParam`. An unknown letter is
  ignored or logged. Such a field has no null check.

## Record Classes

A game's classes are in `falcom/ed9/games/<game>/tbl/schema/`, one file per section, named exactly for it
(`QuestTitle.py`); a comment above each class names the tables that hold it. `tbl/schema_all.py` imports every class by
name, and it is the one module everything else imports. A class's `DESCRIPTOR` lists its fields in record order; each
kind is a letter or two, defined in `FIELD_KINDS` (`parser/tbl.py`), with a key at the top of every `schema_all.py`. A
new kind updates each key.

`sora2`'s `schema_all.py` star-imports `sora1`'s, then imports its own classes, which are what differs, since the two
are remakes in one series; a class of the same name replaces `sora1`'s. `kuro1`, `kuro2` and `kai1` are a separate
group: they do not build on these files.

Adding a table:

1. Find the section's name and record size in the file's header.
2. Write the class in the earliest game of the group that has it, in a file named for the section, and import the class
   in that game's `schema_all.py`: without that the table stays raw. Name the class for the section. A second size of
   one section gets its own class in the same file, imported the same way, with `SECTION` set and its size as a suffix
   (`NPCParam98`), since the name alone cannot pick it.
3. Name a field only where the data or the exe shows what it is; name the rest by size and offset (`str08`, `uint32_44`,
   `arr16_10`). The exe read is `sora2`'s, so a name in `sora1`'s class rests on the offsets agreeing.
4. Run `tbl2py.py` on the table in every game of the group, and fix anything in `problems`.
5. Where a later game's layout differs, define the class in that game's `schema/` folder. A size can match and the
   layout still differ: `MonsterSettingParam` `0xa8` is one layout in `sora1` and another in `sora2`.

Naming fields:

- **A name** comes from what the exe shows a field doing, or from strings that leave no doubt what it holds. A meaning
  that is only a reading keeps the field's offset name, but for positions.
- **An offset name** gives the size and offset: `uint8_40`, `uint16_02`, `uint32_44`, `uint64_28`, `int16_166`,
  `float32_2c`, `str08`, `arr16_10`, `arrf32_78`.
- **Padding** is only the zero bytes a narrow field leaves in the slot it shares. Any other unread bytes stay a field,
  zero or not, so a script can still set them.

## What the Checks Prove

| Check | Catches | Does not catch |
|---|---|---|
| Name and record size | A size no class has: reported if the name has a class at another size | A changed layout of the same size |
| String and array pointers | A pointer outside the data block, an unaligned array, text that is not UTF-8: reported, and the section stays raw | A number misread as a pointer that lands on valid text; the next check usually does |
| Data block accounting | A gap or overlap: every byte must belong to one item, or be padding before one | Anything when a section of the file is raw, since its pointers are unknown |

So a table with no problems has the right record size and the right pointer fields. The checks say nothing about the
rest: two 2-byte fields read as one 4-byte field, or an integer read as a float of the same width, give no error, and a
field's name is only a reading of its values. A wrong type gives a wrong value in `entries`, not a wrong file, so a
byte-for-byte rebuild does not catch it either.

## Character IDs

`NameTableData` (`t_name.tbl`) lists characters and their costumes. What is known about its IDs, from the same read of
the `sora2` exe, with the counts from `sora2`'s tables and all 1,082 scripts:

- `chrId` is the ID `chr_create` looks up, read as 2 bytes. Other `chr_*` calls find the live character, not a row.
- **Choosing a row:** `chr_create` tries its ID against `chrId`, then its third argument against `statusKey`, then its
  second against `model`. The first row that matches wins; no match leaves the character with no row, which is allowed.
- `0xFFFF` marks a row with no ID of its own, mostly costumes, reached by text.
- An ID may repeat, and a name repeats often (`Estelle` has three IDs), so a name is not a key.
- **IDs outside the table:** of 7,401 `chr_create` calls, 53% pass an ID in the table, 28% one that is not, and 20% a
  variable. An ID that is not in the table often serves several models (`21050` takes 56), so it names a slot, not a
  character.
- **NPC rows:** an `NPCParam` row makes a character with its `chrId`. Its `model`, when set, works as in `chr_create`;
  when empty, a non-zero `overrideChrId` replaces the ID for the row lookup. `overrideChrId` is set only on a `chrId`
  outside the table, and such a `chrId` can have several, so the name belongs to the row, not the ID. A row with `X` in
  `flags` is not created, but another row's `lookPoint` can name it.
- **Pseudo IDs:** `65534` (the thread's owner) and others are resolved before any lookup, and no `chrId` but `0xFFFF`
  falls among them. 22000..22032 are an owner's local characters; no `chrId` is in that range either.

`falcom/ed9/tools/gen_tables.py` builds `ChrIdTable` from this table, `ItemIdTable` from `t_item.tbl` and `CraftIdTable`
from `t_skill.tbl`, in the game's `metadata/` as `chr_table.py`, `item_table.py` and `craft_table.py` (gitignored,
`sora2` only so far): each one dict that maps each name to its ID and each ID to its name. The first row of an ID wins,
as in the game; `0xFFFF` rows, pseudo IDs and crafts with no name stay out. The first ID of a repeated name, in file
order, keeps it plain; a later one adds its ID in hex (`Estelle`, `Estelle_00A5`). Nothing prints these names yet.

## Games on This Format

| Game | Tables | Section names | Layouts (name and size) |
|---|---|---|---|
| `sora1` | 237 | 151 | 152 |
| `sora2` | 315 | 203 | 207 |

The two share 132 layouts by name and size, most of `sora1`'s; equal size does not prove equal fields. `sora2` adds
tables such as `TalkTableData` and the `Viewer*` family, and changes others (`ItemTableData` `0xe8` to `0x100`). The
container fits every table of both games. `kuro1`, `kuro2` and `kai1` have tables too (`table_en/`, `kai1`:
`table_eng/`), not read.
