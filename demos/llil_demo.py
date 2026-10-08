#!/usr/bin/env python3
'''LLIL Demo - Expression-based Architecture'''

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from ir.llil import *
from falcom import *

DOT_FILE_NAME = 'cfg.dot'

# Each callee's declared parameter count - the demo's stand-in for the script's function table
DECLARED_PARAMS = {
    'map_event_box_set_enable'    : 2,
    'avoice_play'                 : 1,
    'screen_dof_set_enable'       : 1,
    'screen_dof_set_focus_range'  : 2,
    'screen_dof_set_blur_level'   : 1,
    'TALK_BEGIN'                  : 2,
    'menu_create'                 : 4,
    'menu_additem'                : 3,
    'menu_open'                   : 4,
    'menu_wait'                   : 1,
    'menu_close'                  : 1,
    'fade_out'                    : 4,
    'fade_wait'                   : 1,
    'chr_set_pos'                 : 5,
    'camera_rotate_chr'           : 7,
    'TALK_END'                    : 0,
    'fade_in'                     : 4,
}


def create_AV_04_0017():
    '''AV_04_0017 - Strict 1:1 translation from real game bytecode'''

    # Create builder and function
    builder = FalcomVMBuilder()
    builder.create_function('AV_04_0017', 0x243C5, num_params = 0)

    # Create all blocks upfront with labels (automatically added to function)
    entry_block = builder.create_basic_block(0x243C5, 'AV_04_0017')
    loc_243E3 = builder.create_basic_block(0x243E3, 'loc_243E3')
    loc_243FB = builder.create_basic_block(0x243FB, 'loc_243FB')

    # === BLOCK 0: Entry - map_event_box_set_enable call ===
    # sp auto-set to num_params (0), fp = 0
    builder.set_current_block(entry_block)

    # DEBUG_SET_LINENO(2519)
    builder.debug_line(2519)
    # PUSH_CURRENT_FUNC_ID()
    builder.push_func_id()
    # PUSH_RET_ADDR('loc_243E3')
    builder.push_ret_addr(loc_243E3)
    # PUSH_INT(0)
    builder.push_int(0)
    # PUSH_STR('AV_04_0017')
    builder.push_str('AV_04_0017')
    # CALL(map_event_box_set_enable)
    builder.call('map_event_box_set_enable', DECLARED_PARAMS['map_event_box_set_enable'])
    # Falls through to BLOCK 1

    # === BLOCK 1: loc_243E3 - avoice_play call ===
    builder.set_current_block(loc_243E3)

    # DEBUG_SET_LINENO(2520)
    builder.debug_line(2520)
    # PUSH_CURRENT_FUNC_ID()
    builder.push_func_id()
    # PUSH_RET_ADDR('loc_243FB')
    builder.push_ret_addr(loc_243FB)
    # PUSH_INT(427)
    builder.push_int(427)
    # CALL(avoice_play)
    builder.call('avoice_play', DECLARED_PARAMS['avoice_play'])
    # Falls through to BLOCK 2

    # === BLOCK 2: loc_243FB - Return ===
    builder.set_current_block(loc_243FB)

    # DEBUG_SET_LINENO(2521)
    builder.debug_line(2521)
    # PUSH(0x00000000)
    builder.push_int(0)
    # SET_REG(0)
    builder.set_reg(0)
    # RETURN()
    builder.ret()

    # Finalize and return function
    return builder.finalize()


def create_DOF_ON():
    '''DOF_ON - Strict 1:1 translation from real game bytecode'''

    # Create builder and function
    builder = FalcomVMBuilder()
    builder.create_function('DOF_ON', 0x1FFDB6, num_params = 2)

    # Create all blocks upfront with labels (automatically added to function)
    entry_block = builder.create_basic_block(0x1FFDB6, 'DOF_ON')
    loc_1FFDCB = builder.create_basic_block(0x1FFDCB, 'loc_1FFDCB')
    nonzero_path = builder.create_basic_block(0x1FFDD8)  # Uses default label loc_1FFDD8
    loc_1FFE02 = builder.create_basic_block(0x1FFE02, 'loc_1FFE02')
    loc_1FFE07 = builder.create_basic_block(0x1FFE07, 'loc_1FFE07')
    loc_1FFE20 = builder.create_basic_block(0x1FFE20, 'loc_1FFE20')
    loc_1FFE35 = builder.create_basic_block(0x1FFE35, 'loc_1FFE35')



    # === BLOCK 0: Entry - Enable DOF ===
    # DOF_ON has 2 parameters (arg1, arg2)
    # sp auto-set to num_params (2), fp = 0
    # Parameters: STACK[fp + 0] = STACK[0] = arg1, STACK[fp + 1] = STACK[1] = arg2
    builder.set_current_block(entry_block)

    # PUSH_CURRENT_FUNC_ID()
    builder.push_func_id()
    # PUSH_RET_ADDR('loc_1FFDCB')
    builder.push_ret_addr(loc_1FFDCB)
    # PUSH_INT(1)
    builder.push_int(1)
    # CALL(screen_dof_set_enable)
    builder.call('screen_dof_set_enable', DECLARED_PARAMS['screen_dof_set_enable'])
    # Falls through to BLOCK 1

    # === BLOCK 1: loc_1FFDCB - Check arg2 == 0 ===
    builder.set_current_block(loc_1FFDCB)

    # LOAD_STACK(-8)
    builder.load_stack(-8)
    # PUSH_INT(0)
    builder.push_int(0)
    # EQ()
    builder.eq()
    # POP_JMP_ZERO('loc_1FFE07')
    # If zero (equal): jump to loc_1FFE07, else fall through to nonzero_path
    builder.pop_jmp_zero(loc_1FFE07, nonzero_path)

    # === BLOCK 2: Nonzero path - Calculate focus range ===
    builder.set_current_block(nonzero_path)

    # PUSH_CURRENT_FUNC_ID()
    builder.push_func_id()
    # PUSH_RET_ADDR('loc_1FFE02')
    builder.push_ret_addr(loc_1FFE02)
    # LOAD_STACK(-12)
    builder.load_stack(-12)
    # LOAD_STACK(-16)
    builder.load_stack(-16)
    # PUSH_FLOAT(0.1)
    builder.push(builder.const_float(0.1))
    # MUL()
    builder.mul()
    # ADD()
    builder.add()
    # LOAD_STACK(-16)
    builder.load_stack(-16)
    # CALL(screen_dof_set_focus_range)
    builder.call('screen_dof_set_focus_range', DECLARED_PARAMS['screen_dof_set_focus_range'])
    # Falls through to BLOCK 3

    # === BLOCK 3: loc_1FFE02 - Jump to merge point ===
    builder.set_current_block(loc_1FFE02)

    # JMP('loc_1FFE20')
    builder.jmp(loc_1FFE20)

    # === BLOCK 4: loc_1FFE07 - Zero path, simple focus range ===
    builder.set_current_block(loc_1FFE07)

    # PUSH_CURRENT_FUNC_ID()
    builder.push_func_id()
    # PUSH_RET_ADDR('loc_1FFE20')
    builder.push_ret_addr(loc_1FFE20)
    # LOAD_STACK(-12)
    builder.load_stack(-12)
    # LOAD_STACK(-20)
    builder.load_stack(-20)
    # CALL(screen_dof_set_focus_range)
    builder.call('screen_dof_set_focus_range', DECLARED_PARAMS['screen_dof_set_focus_range'])
    # Falls through to BLOCK 5

    # === BLOCK 5: loc_1FFE20 - Merge point, set blur level ===
    builder.set_current_block(loc_1FFE20)

    # PUSH_CURRENT_FUNC_ID()
    builder.push_func_id()
    # PUSH_RET_ADDR('loc_1FFE35')
    builder.push_ret_addr(loc_1FFE35)
    # PUSH_INT(3)
    builder.push_int(3)
    # CALL(screen_dof_set_blur_level)
    builder.call('screen_dof_set_blur_level', DECLARED_PARAMS['screen_dof_set_blur_level'])
    # Falls through to BLOCK 6

    # === BLOCK 6: loc_1FFE35 - Return ===
    builder.set_current_block(loc_1FFE35)

    # PUSH(0x00000000)
    builder.push_int(0)
    # SET_REG(0)
    builder.set_reg(0)
    # POP(8) - pops 8 bytes from stack
    builder.pop_n(2)  # 8 bytes = 2 words
    # RETURN()
    builder.ret()

    # Finalize and return function
    return builder.finalize()


def create_sound_play_se():
    '''sound_play_se - Strict 1:1 translation from real game bytecode'''

    # Create builder and function
    builder = FalcomVMBuilder()
    builder.create_function('sound_play_se', 0x149B2, num_params = 8)

    # Create single block with label (automatically added to function)
    entry_block = builder.create_basic_block(0x149B2, 'sound_play_se')



    # === BLOCK 0: Entry - SYSCALL ===
    # Function has 8 parameters (already pushed by caller)
    # sp auto-set to num_params (8), fp = 0
    # Parameters: STACK[fp + 0..7] = STACK[0..7]
    builder.set_current_block(entry_block)

    # LOAD_STACK(-32) x 8 - Load all 8 parameters
    # Will auto-detect and use fp-relative: STACK[fp + 0..7]
    for i in range(8):
        builder.load_frame(i * WORD_SIZE)  # Load STACK[fp + i] = STACK[i]

    # SYSCALL(6, 0x10, 0x08)
    builder.syscall(6, 0x10, 0x08)

    # POP(32) - Clean up 8 words pushed by syscall
    builder.pop_n(8)

    # PUSH(0x00000000)
    builder.push_int(0)
    # SET_REG(0)
    builder.set_reg(0)

    # POP(32) - Clean up 8 parameters (8 words = 32 bytes)
    builder.pop_n(8)

    # RETURN()
    builder.ret()

    # Finalize and return function
    return builder.finalize()


def create_Dummy_m3010_talk0():
    '''Dummy_m3010_talk0 - Complex menu system with nested conditionals'''

    # Create builder and function
    builder = FalcomVMBuilder()
    builder.create_function('Dummy_m3010_talk0', 0x8ACC7, num_params=0)

    # Create all blocks upfront
    entry = builder.create_basic_block(0x8ACC7, 'Dummy_m3010_talk0')
    loc_8ACE5 = builder.create_basic_block(0x8ACE5, 'loc_8ACE5')
    loc_8AD0F = builder.create_basic_block(0x8AD0F, 'loc_8AD0F')
    loc_8AD33 = builder.create_basic_block(0x8AD33, 'loc_8AD33')
    loc_8AD57 = builder.create_basic_block(0x8AD57, 'loc_8AD57')
    loc_8AD7B = builder.create_basic_block(0x8AD7B, 'loc_8AD7B')
    loc_8ADA5 = builder.create_basic_block(0x8ADA5, 'loc_8ADA5')
    loc_8ADC3 = builder.create_basic_block(0x8ADC3, 'loc_8ADC3')
    loc_8ADE2 = builder.create_basic_block(0x8ADE2, 'loc_8ADE2')
    fade_out_block = builder.create_basic_block(0x8AE08, 'fade_out_block')  # Fall-through from loc_8ADE2
    loc_8AE20 = builder.create_basic_block(0x8AE20, 'loc_8AE20')
    loc_8AE38 = builder.create_basic_block(0x8AE38, 'loc_8AE38')  # check_case_0
    case_0_chr_set_pos = builder.create_basic_block(0x8AE58, 'case_0_chr_set_pos')  # Fall-through for case 0
    loc_8AE7C = builder.create_basic_block(0x8AE7C, 'loc_8AE7C')
    loc_8AEB8 = builder.create_basic_block(0x8AEB8, 'loc_8AEB8')
    loc_8AEBD = builder.create_basic_block(0x8AEBD, 'loc_8AEBD')  # check_case_1
    case_1_chr_set_pos = builder.create_basic_block(0x8AEE1, 'case_1_chr_set_pos')  # Fall-through for case 1
    loc_8AF01 = builder.create_basic_block(0x8AF01, 'loc_8AF01')
    loc_8AF3D = builder.create_basic_block(0x8AF3D, 'loc_8AF3D')
    loc_8AF42 = builder.create_basic_block(0x8AF42, 'loc_8AF42')  # check_case_2
    loc_8AFAA = builder.create_basic_block(0x8AFAA, 'loc_8AFAA')  # Fall-through: chr_set_pos in case 2
    loc_8AF86 = builder.create_basic_block(0x8AF86, 'loc_8AF86')  # camera_rotate_chr in case 2
    loc_8AFC2 = builder.create_basic_block(0x8AFC2, 'loc_8AFC2')  # Main merge point
    loc_8AFD4 = builder.create_basic_block(0x8AFD4, 'loc_8AFD4')
    check_fade_in = builder.create_basic_block(0x8AFE4, 'check_fade_in')
    loc_8B012 = builder.create_basic_block(0x8B012, 'loc_8B012')  # Final block

    # === BLOCK 0: Entry - TALK_BEGIN ===
    builder.set_current_block(entry)
    builder.debug_line(10792)
    builder.push_func_id()
    builder.push_ret_addr(loc_8ACE5)
    builder.push(builder.const_float(4.0))
    builder.push_int(0)
    builder.call('TALK_BEGIN', DECLARED_PARAMS['TALK_BEGIN'])

    # === BLOCK 1: loc_8ACE5 - menu_create ===
    builder.set_current_block(loc_8ACE5)
    builder.debug_line(10795)
    builder.push_func_id()
    builder.push_ret_addr(loc_8AD0F)
    builder.push_int(24)
    builder.push_int(0)
    builder.push_int(0)
    builder.push_int(0)
    builder.call('menu_create', DECLARED_PARAMS['menu_create'])

    # === BLOCK 2: loc_8AD0F - menu_additem (ボス戦前) ===
    builder.set_current_block(loc_8AD0F)
    builder.debug_line(10796)
    builder.push_func_id()
    builder.push_ret_addr(loc_8AD33)
    builder.push_int(2)
    builder.push_str('ボス戦前')
    builder.push_int(0)
    builder.call('menu_additem', DECLARED_PARAMS['menu_additem'])

    # === BLOCK 3: loc_8AD33 - menu_additem (中間地点②) ===
    builder.set_current_block(loc_8AD33)
    builder.debug_line(10797)
    builder.push_func_id()
    builder.push_ret_addr(loc_8AD57)
    builder.push_int(1)
    builder.push_str('中間地点②')
    builder.push_int(0)
    builder.call('menu_additem', DECLARED_PARAMS['menu_additem'])

    # === BLOCK 4: loc_8AD57 - menu_additem (中間地点①) ===
    builder.set_current_block(loc_8AD57)
    builder.debug_line(10798)
    builder.push_func_id()
    builder.push_ret_addr(loc_8AD7B)
    builder.push_int(0)
    builder.push_str('中間地点①')
    builder.push_int(0)
    builder.call('menu_additem', DECLARED_PARAMS['menu_additem'])

    # === BLOCK 5: loc_8AD7B - menu_open ===
    builder.set_current_block(loc_8AD7B)
    builder.debug_line(10800)
    builder.push_func_id()
    builder.push_ret_addr(loc_8ADA5)
    builder.push_int(1)
    builder.push_int(-1)
    builder.push_int(-1)
    builder.push_int(0)
    builder.call('menu_open', DECLARED_PARAMS['menu_open'])

    # === BLOCK 6: loc_8ADA5 - menu_wait and store result ===
    builder.set_current_block(loc_8ADA5)
    builder.debug_line(10802)
    builder.push_int(0)  # PUSH(0x00000000)
    builder.push_func_id()
    builder.push_ret_addr(loc_8ADC3)
    builder.push_int(0)
    builder.call('menu_wait', DECLARED_PARAMS['menu_wait'])

    # === BLOCK 7: loc_8ADC3 - GET_REG(0), POP_TO(-4), menu_close ===
    builder.set_current_block(loc_8ADC3)
    builder.get_reg(0)
    # POP_TO(-4) means: stack[sp + opr] = pop()
    # After pop, sp is already decremented, so stack[sp + (-4)] = popped_value
    builder.pop_to(-4)
    builder.debug_line(10803)
    builder.push_func_id()
    builder.push_ret_addr(loc_8ADE2)
    builder.push_int(0)
    builder.call('menu_close', DECLARED_PARAMS['menu_close'])

    # === BLOCK 8: loc_8ADE2 - Check if selection >= 0 ===
    builder.set_current_block(loc_8ADE2)
    builder.debug_line(10805)
    builder.load_stack(-4)
    builder.push_int(0)
    builder.ge()  # GE() operation
    # POP_JMP_ZERO: if result is zero, jump to loc_8AFC2, else continue to fade_out_block
    builder.pop_jmp_zero(loc_8AFC2, fade_out_block)

    # === BLOCK 9: fade_out_block - Fall-through: call fade_out ===
    builder.set_current_block(fade_out_block)
    builder.debug_line(10807)
    builder.push_func_id()
    builder.push_ret_addr(loc_8AE20)
    builder.push_int(0)
    builder.push(builder.const_float(1.0))
    builder.push_int(0)
    builder.push(builder.const_float(0.5))
    builder.call('fade_out', DECLARED_PARAMS['fade_out'])

    # === BLOCK 10: loc_8AE20 - fade_out return: call fade_wait ===
    builder.set_current_block(loc_8AE20)
    builder.debug_line(10808)
    builder.push_func_id()
    builder.push_ret_addr(loc_8AE38)
    builder.push_int(0)
    builder.call('fade_wait', DECLARED_PARAMS['fade_wait'])

    # === BLOCK 11: loc_8AE38 - Check if selection == 0 ===
    builder.set_current_block(loc_8AE38)
    builder.debug_line(10810)
    builder.load_stack(-4)
    builder.push_int(0)
    builder.eq()
    # POP_JMP_ZERO: if not equal, jump to loc_8AEBD, else continue to case_0_chr_set_pos
    builder.pop_jmp_zero(loc_8AEBD, case_0_chr_set_pos)

    # === BLOCK 12: case_0_chr_set_pos - Fall-through: call chr_set_pos ===
    builder.set_current_block(case_0_chr_set_pos)
    builder.debug_line(10811)
    builder.push_func_id()
    builder.push_ret_addr(loc_8AE7C)
    builder.push(builder.const_float(188.359))
    builder.push(builder.const_float(122.862))
    builder.push(builder.const_float(1.918))
    builder.push(builder.const_float(-134.292))
    builder.push_int(65000)
    builder.call('chr_set_pos', DECLARED_PARAMS['chr_set_pos'])

    # === BLOCK 13: loc_8AE7C - camera_rotate_chr ===
    builder.set_current_block(loc_8AE7C)
    builder.debug_line(10812)
    builder.push_func_id()
    builder.push_ret_addr(loc_8AEB8)
    builder.push_int(-1)
    builder.push_int(3)
    builder.push_int(0)
    builder.push(builder.const_float(0.0))
    builder.push(builder.const_float(0.0))
    builder.push(builder.const_float(0.0))
    builder.push_int(65000)
    builder.call('camera_rotate_chr', DECLARED_PARAMS['camera_rotate_chr'])

    # === BLOCK 14: loc_8AEB8 - Jump to merge point ===
    builder.set_current_block(loc_8AEB8)
    builder.jmp(loc_8AFC2)

    # === BLOCK 15: loc_8AEBD - Check if selection == 1 ===
    builder.set_current_block(loc_8AEBD)
    builder.debug_line(10814)
    builder.load_stack(-4)
    builder.push_int(1)
    builder.eq()
    # POP_JMP_ZERO: if not equal, jump to loc_8AF42, else continue to case_1_chr_set_pos
    builder.pop_jmp_zero(loc_8AF42, case_1_chr_set_pos)

    # === BLOCK 15: case_1_chr_set_pos - Fall-through: call chr_set_pos ===
    builder.set_current_block(case_1_chr_set_pos)
    builder.debug_line(10815)
    builder.push_func_id()
    builder.push_ret_addr(loc_8AF01)
    builder.push(builder.const_float(62.994))
    builder.push(builder.const_float(-62.892))
    builder.push(builder.const_float(-0.297))
    builder.push(builder.const_float(-85.992))
    builder.push_int(65000)
    builder.call('chr_set_pos', DECLARED_PARAMS['chr_set_pos'])

    # === BLOCK 16: loc_8AF01 - camera_rotate_chr ===
    builder.set_current_block(loc_8AF01)
    builder.debug_line(10816)
    builder.push_func_id()
    builder.push_ret_addr(loc_8AF3D)
    builder.push_int(-1)
    builder.push_int(3)
    builder.push_int(0)
    builder.push(builder.const_float(0.0))
    builder.push(builder.const_float(0.0))
    builder.push(builder.const_float(0.0))
    builder.push_int(65000)
    builder.call('camera_rotate_chr', DECLARED_PARAMS['camera_rotate_chr'])

    # === BLOCK 17: loc_8AF3D - Jump to merge point ===
    builder.set_current_block(loc_8AF3D)
    builder.jmp(loc_8AFC2)

    # === BLOCK 18: loc_8AF42 - Check if selection == 2, then chr_set_pos ===
    builder.set_current_block(loc_8AF42)
    builder.debug_line(10818)
    builder.load_stack(-4)
    builder.push_int(2)
    builder.eq()
    # POP_JMP_ZERO: if not equal, jump to loc_8AFC2, else continue with chr_set_pos
    builder.pop_jmp_zero(loc_8AFC2, loc_8AFAA)

    # === BLOCK 18: loc_8AFAA - Case 2: chr_set_pos ===
    builder.set_current_block(loc_8AFAA)
    builder.debug_line(10819)
    builder.push_func_id()
    builder.push_ret_addr(loc_8AF86)  # Return to loc_8AF86 for second call
    builder.push(builder.const_float(112.963))
    builder.push(builder.const_float(-157.72))
    builder.push(builder.const_float(-0.283))
    builder.push(builder.const_float(-5.976))
    builder.push_int(65000)
    builder.call('chr_set_pos', DECLARED_PARAMS['chr_set_pos'])

    # === BLOCK 19: loc_8AF86 - Case 2: camera_rotate_chr ===
    builder.set_current_block(loc_8AF86)
    builder.debug_line(10820)
    builder.push_func_id()
    builder.push_ret_addr(loc_8AFC2)
    builder.push_int(-1)
    builder.push_int(3)
    builder.push_int(0)
    builder.push(builder.const_float(0.0))
    builder.push(builder.const_float(0.0))
    builder.push(builder.const_float(0.0))
    builder.push_int(65000)
    builder.call('camera_rotate_chr', DECLARED_PARAMS['camera_rotate_chr'])

    # === BLOCK 20: loc_8AFC2 - TALK_END (merge point from all cases) ===
    builder.set_current_block(loc_8AFC2)
    builder.debug_line(10824)
    builder.push_func_id()
    builder.push_ret_addr(loc_8AFD4)
    builder.call('TALK_END', DECLARED_PARAMS['TALK_END'])

    # === BLOCK 21: loc_8AFD4 - Check if selection >= 0 for fade_in ===
    builder.set_current_block(loc_8AFD4)
    builder.debug_line(10826)
    builder.load_stack(-4)
    builder.push_int(0)
    builder.ge()
    # POP_JMP_ZERO: if result is zero, jump to loc_8B012, else continue to check_fade_in
    builder.pop_jmp_zero(loc_8B012, check_fade_in)

    # === BLOCK 22: check_fade_in - fade_in ===
    builder.set_current_block(check_fade_in)
    builder.debug_line(10827)
    builder.push_func_id()
    builder.push_ret_addr(loc_8B012)
    builder.push_int(0)
    builder.push(builder.const_float(0.0))
    builder.push_int(0)
    builder.push(builder.const_float(0.5))
    builder.call('fade_in', DECLARED_PARAMS['fade_in'])

    # === BLOCK 23: loc_8B012 - Return (final merge point) ===
    builder.set_current_block(loc_8B012)
    builder.debug_line(10830)
    builder.push_int(0)
    builder.set_reg(0)
    # POP(4) - pop 4 bytes (1 word) from stack
    builder.pop_n(1)
    builder.ret()

    # Finalize and return function
    return builder.finalize()


def test_AV_04_0017():
    '''Test 1: AV_04_0017 - Simple linear function'''
    print('\n🧪 Test 1: AV_04_0017 - Simple Linear Function')
    print('-' * 60)
    print('Source: m4000.py (id: 0x0000 offset: 0x243C5)')
    print('3 blocks, no branching, 2 function calls')

    func1 = create_AV_04_0017()
    print('\n' + '\n'.join(FalcomLLILFormatter.format_llil_function(func1)))
    with open(DOT_FILE_NAME, 'w') as f:
        f.write(FalcomLLILFormatter.to_dot(func1))


def test_DOF_ON():
    '''Test 2: DOF_ON - Complex control flow'''
    print('\n🧪 Test 2: DOF_ON - Complex Control Flow')
    print('-' * 60)
    print('Source: c0000.py (id: 0x003F offset: 0x1FFDB6)')
    print('7 blocks, conditional branching, merge points')

    func2 = create_DOF_ON()
    print('\n' + '\n'.join(FalcomLLILFormatter.format_llil_function(func2)))

    # Generate CFG visualization
    dot = FalcomLLILFormatter.to_dot(func2)
    with open(DOT_FILE_NAME, 'w') as f:
        f.write(dot)
    print('\n📊 CFG saved to DOF_ON_cfg.dot')
    print('   View online: https://dreampuf.github.io/GraphvizOnline/')
    print('   Or render: dot -Tpng DOF_ON_cfg.dot -o DOF_ON_cfg.png')


def test_sound_play_se():
    '''Test 3: sound_play_se - SYSCALL with multiple parameters'''
    print('\n🧪 Test 3: sound_play_se - SYSCALL with Multiple Parameters')
    print('-' * 60)
    print('Source: c0000.py (id: 0x008F offset: 0x149B2)')
    print('8 parameters, 1 block, demonstrates SYSCALL and parameter loading')

    func3 = create_sound_play_se()
    print('\n' + '\n'.join(FalcomLLILFormatter.format_llil_function(func3)))


def test_Dummy_m3010_talk0():
    '''Test 4: Dummy_m3010_talk0 - Complex menu system'''
    print('\n🧪 Test 4: Dummy_m3010_talk0 - Complex Menu System')
    print('-' * 60)
    print('Source: m3010.py (id: 0x0005 offset: 0x8ACC7)')
    print('Multiple conditional branches, menu system, nested if-else')

    func4 = create_Dummy_m3010_talk0()
    print('\n' + '\n'.join(FalcomLLILFormatter.format_llil_function(func4)))

    # Generate CFG visualization
    dot = FalcomLLILFormatter.to_dot(func4)
    with open(DOT_FILE_NAME, 'w') as f:
        f.write(dot)
    print('\n📊 CFG saved to Dummy_m3010_talk0_cfg.dot')
    print('   View online: https://dreampuf.github.io/GraphvizOnline/')
    print('   Or render: dot -Tpng Dummy_m3010_talk0_cfg.dot -o Dummy_m3010_talk0_cfg.png')


def create_EV_06_37_00():
    builder = FalcomVMBuilder()
    builder.create_function('EV_06_37_00', 0x16AC50, num_params=0)

    # Create all blocks
    entry = builder.create_basic_block(0x16AC50, 'EV_06_37_00')

    # === BLOCK 0: Entry - Call rand(0.0, 1.0) ===
    builder.set_current_block(entry)

    # DEBUG_SET_LINENO(20967)
    builder.debug_line(20967)
    builder.push_int(0)
    builder.push_int(1)
    builder.push_int(1)
    builder.add()
    builder.pop_to(-4)
    builder.set_reg(0)

    # RETURN()
    builder.ret()

    return builder.finalize()


def create_test_conditional():
    '''Test function - Conditional branches with POP_JMP_NOT_ZERO and POP_JMP_ZERO'''
    builder = FalcomVMBuilder()
    builder.create_function('test_conditional', 0x5BDA0, num_params=0)

    # Create blocks
    entry = builder.create_basic_block(0x5BDA0, 'entry')
    bb_check_eq_2 = builder.create_basic_block(0x5BDA8, 'check2')
    bb_cond_1 = builder.create_basic_block(0x5BDB1, 'loc_5BDB1')
    bb_cond_2 = builder.create_basic_block(0x5BDC1, 'loc_5BDC1')

    # === BLOCK 0: Entry - check if REG[0] == 1 ===
    builder.set_current_block(entry)
    builder.get_reg(0)
    builder.push_int(1)
    builder.eq()
    builder.pop_jmp_not_zero(bb_cond_1, bb_check_eq_2)

    # === BLOCK 1: check2 - check if REG[0] == 2 ===
    builder.set_current_block(bb_check_eq_2)
    builder.get_reg(0)
    builder.push_int(2)
    builder.eq()
    builder.pop_jmp_zero(bb_cond_2, bb_cond_1)

    builder.set_current_block(bb_cond_2)
    builder.load_global(0)
    builder.set_global(0)
    builder.jmp(bb_cond_1)

    # === BLOCK 2: loc_5BDB1 - Return ===
    builder.set_current_block(bb_cond_1)
    builder.push_int(0)
    builder.set_reg(0)  # Set return value to REG[0]
    builder.ret()

    return builder.finalize()


def create_TALK_BEGIN():
    '''TALK_BEGIN - Function call with caller context and module call'''
    builder = FalcomVMBuilder()
    builder.create_function('TALK_BEGIN', 0x54F50, num_params = 2)

    # Create blocks
    entry = builder.create_basic_block(0x54F50, 'TALK_BEGIN')
    loc_54F6B = builder.create_basic_block(0x54F6B, 'loc_54F6B')

    # === BLOCK 0: Entry ===
    builder.set_current_block(entry)

    # PUSH_CALLER_CONTEXT('loc_54F6B')
    builder.push_caller_frame(loc_54F6B)

    # LOAD_STACK(-28)
    builder.load_stack(-28)
    # PUSH_INT(0)
    builder.push_int(0)
    # LOAD_STACK(-32)
    builder.load_stack(-32)

    # CALL_SCRIPT('system', 'OnTalkBegin', 3)
    builder.call_script('system', 'OnTalkBegin', 3)

    # === BLOCK 1: loc_54F6B ===
    builder.set_current_block(loc_54F6B)

    # PUSH(0x00000000)
    builder.push_int(0x00000000, is_hex = True)
    # SET_REG(0)
    builder.set_reg(0)
    # POP(8)
    builder.pop_bytes(8)

    # RETURN()
    builder.ret()

    return builder.finalize()


def test_TALK_BEGIN():
    '''Test TALK_BEGIN function'''
    print('\n🧪 Test 5: TALK_BEGIN - Module Calls')
    print('-' * 60)
    print('Function demonstrating:')
    print('- CALL_SCRIPT: call external script function')
    print('- LOAD_STACK: load from stack with negative offset (parameters)')
    print('- Function parameters and caller context')
    print()

    func5 = create_TALK_BEGIN()
    print('\n' + '\n'.join(FalcomLLILFormatter.format_llil_function(func5)))

    dot = FalcomLLILFormatter.to_dot(func5)
    with open(DOT_FILE_NAME, 'w') as f:
        f.write(dot)


def test_conditional():
    '''Test conditional branches'''
    print('\n🧪 Test 6: Conditional Branches')
    print('-' * 60)
    print('Function demonstrating:')
    print('- POP_JMP_NOT_ZERO: branch if value != 0')
    print('- POP_JMP_ZERO: branch if value == 0')
    print('- Multi-block control flow')
    print()

    func5 = create_test_conditional()
    print('\n' + '\n'.join(FalcomLLILFormatter.format_llil_function(func5)))

    dot = FalcomLLILFormatter.to_dot(func5)
    with open(DOT_FILE_NAME, 'w') as f:
        f.write(dot)


def test_EV_06_37_00():
    '''Test EV_06_37_00 function'''
    print('\n🧪 Test 7: EV_06_37_00 - Global Variables')
    print('-' * 60)
    print('Function demonstrating:')
    print('- LOAD_GLOBAL: read from global variable array')
    print('- SET_GLOBAL: write to global variable array')
    print('- Global variables are Falcom-specific extensions')
    print()

    func6 = create_EV_06_37_00()
    print('\n' + '\n'.join(FalcomLLILFormatter.format_llil_function(func6)))

    dot = FalcomLLILFormatter.to_dot(func6)
    with open(DOT_FILE_NAME, 'w') as f:
        f.write(dot)


def main():
    # Test individual functions (comment/uncomment as needed)
    # test_AV_04_0017()
    # test_DOF_ON()
    # test_sound_play_se()
    # test_Dummy_m3010_talk0()
    # test_TALK_BEGIN()
    # test_conditional()
    test_EV_06_37_00()


if __name__ == '__main__':
    main()
