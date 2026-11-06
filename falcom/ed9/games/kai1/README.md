# kai1

Outputs are keyed by script name, so two scripts with one name in different folders overwrite each other. `kai1` has six such
names: `d5030`, `d5300`, `d5310`, `d5320`, `d5330` and `d5390`. `script_eng/demo/scena/` holds the trial version of each and
`script_eng/scena/` the full game's, and they are different scripts; a run over all of `script_eng` keeps only the full game's.

To keep the trial versions too, give that folder its own output folder:

    python falcom/ed9/games/kai1/scp2py.py falcom/ed9/games/kai1/extracted/script_eng/demo -o <folder>
