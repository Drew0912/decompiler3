"""The HLIL DSL's compile side (docs/dsl/HLIL_DSL.md); the package imports none of its modules. VM-neutral, importing
nothing from falcom.ed9 (a test checks): nodes.py the nodes, keyed by HLIL's operators; calls.py the calls; control.py
If, While, Break and Continue and their blocks; macro_statements.py @macro, a macro's own statements going where its
call's value goes, and where a statement no block holds may stand; build.py and tree.py an HLIL body's build and the
checks of its statements; source_check.py the source check; stubs.py the function stubs. ED9's: ed9_nodes.py its own
nodes (Raw, REGS, Syscall, PopN, DebugInt); lowering.py and llil_sink.py the lowering into its opcodes, through the
writer's opcode functions"""
