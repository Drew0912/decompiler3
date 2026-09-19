# Quickstart: ED9 SCP Script Decompiler

## Prerequisites

- Python 3.14+
- PyYAML (`pip install pyyaml`)

## Basic Usage

### 1. Parse SCP File

```python
from falcom.ed9.parser import ScpParser
from ml import fileio

# Open file
fs = fileio.FileStream()
fs.Open("script.dat")

# Parse SCP structure
parser = ScpParser(fs, "script.dat")
parser.parse()

# Disassemble all functions
functions = parser.disasm_all_functions()
```

### 2. Lift to LLIL

```python
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.llil.llil_builder import FalcomLLILFormatter

# Create lifter
lifter = ED9VMLifter(parser=parser)

# Lift each function
for func in functions:
    llil_func = lifter.lift_function(func)

    # Optional: Output LLIL text
    llil_text = FalcomLLILFormatter.format_llil_function(llil_func)
    print('\n'.join(llil_text))
```

### 3. Convert to MLIL

```python
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from ir.mlil import MLILFormatter

# Convert LLIL → MLIL
mlil_func = convert_falcom_llil_to_mlil(llil_func, parser)

# Optional: Output MLIL text
mlil_text = MLILFormatter.format_function(mlil_func)
print('\n'.join(mlil_text))
```

### 4. Convert to HLIL

```python
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from ir.hlil import HLILFormatter

# Convert MLIL → HLIL (need original function for type info)
hlil_func = convert_falcom_mlil_to_hlil(mlil_func, func)

# Optional: Output HLIL text
hlil_text = HLILFormatter.format_function(hlil_func)
print('\n'.join(hlil_text))
```

### 5. Generate TypeScript

```python
from codegen import generate_typescript

# Generate TypeScript code
typescript_code = generate_typescript(hlil_func)
print(typescript_code)
```

## Using Signature Database

```python
from pathlib import Path
from falcom.ed9.signatures.format_signatures import FormatSignatureDB
from codegen import TypeScriptGenerator

# Load signature database
sig_db = FormatSignatureDB()
sig_db.load_yaml(Path("signatures/ed9.yaml"))

# Set for code generator
TypeScriptGenerator.set_signature_db(sig_db)

# Now generate_typescript() will use signatures
typescript_code = generate_typescript(hlil_func)
```

## Complete Example

```python
#!/usr/bin/env python3
"""Decompile a single SCP file to TypeScript."""

from pathlib import Path
from ml import fileio
from falcom.ed9.parser import ScpParser
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from falcom.ed9.signatures.format_signatures import FormatSignatureDB
from codegen import generate_typescript, TypeScriptGenerator


def decompile_scp(input_path: Path, output_path: Path, sig_path: Path = None):
    """Decompile SCP file to TypeScript."""

    # Load signatures if provided
    if sig_path and sig_path.exists():
        sig_db = FormatSignatureDB()
        sig_db.load_yaml(sig_path)
        TypeScriptGenerator.set_signature_db(sig_db)

    # Parse SCP
    fs = fileio.FileStream()
    fs.Open(str(input_path))

    parser = ScpParser(fs, input_path.name)
    parser.parse()
    functions = parser.disasm_all_functions()

    # Decompile each function
    lifter = ED9VMLifter(parser=parser)
    output_lines = []

    for func in functions:
        # LLIL
        llil_func = lifter.lift_function(func)

        # MLIL
        mlil_func = convert_falcom_llil_to_mlil(llil_func, parser)

        # HLIL
        hlil_func = convert_falcom_mlil_to_hlil(mlil_func, func)

        # TypeScript
        ts_code = generate_typescript(hlil_func)
        output_lines.append(ts_code)
        output_lines.append('')

    # Write output
    output_path.write_text('\n'.join(output_lines), encoding='utf-8')
    print(f"Decompiled {len(functions)} functions to {output_path}")


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python decompile.py <input.dat> [output.ts] [signatures.yaml]")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2]) if len(sys.argv) > 2 else input_file.with_suffix('.ts')
    sig_file = Path(sys.argv[3]) if len(sys.argv) > 3 else None

    decompile_scp(input_file, output_file, sig_file)
```

## Output Files

| Extension | Content | Purpose |
|-----------|---------|---------|
| `.ts` | TypeScript code | Final decompiled output |
| `.llil.asm` | LLIL text | Debug: Low-level IR |
| `.mlil.asm` | MLIL text | Debug: Medium-level IR |
| `.hlil.ts` | HLIL text | Debug: High-level IR |
| `.llil.dot` | LLIL CFG | Debug: GraphViz CFG |
| `.mlil.dot` | MLIL CFG | Debug: GraphViz CFG |

## Signature YAML Format

```yaml
# Define enums
enums:
  SpeakerType:
    0: SPEAKER_NONE
    1: SPEAKER_PLAYER
    2: SPEAKER_NPC

# Define syscalls
syscalls:
  mes_message_talk:
    id: [5, 0]
    params:
      - name: speaker_id
        type: number
        format: SpeakerType
      - name: message
        type: string
    return:
      type: void

# Define functions (optional)
functions:
  calculate_damage:
    params:
      - name: attacker
        type: number
      - name: defender
        type: number
    return:
      type: number
```

## Troubleshooting

### Unknown Opcode Error

```
ValueError: Unknown opcode 0xAB at address 0x1234
```

The script contains an opcode not in the opcode table. Add the opcode definition to `falcom/ed9/disasm/ed9_optable.py`.

### Invalid Magic Error

```
ValueError: Invalid SCP magic: expected '#scp'
```

The file is not a valid SCP script file. Verify the file format.

### Type Inference Warnings

Type conflicts are logged but don't stop decompilation. The output will use `any` type for conflicting variables.

## Running Tests

```bash
python tests/test_scp_parser.py
```

The test processes all `.dat` files in the test directory and generates corresponding output files.
