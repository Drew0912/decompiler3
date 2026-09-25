# Falcom LLIL Spec

> **Outdated draft - does not describe the current builder.** Among other differences: the virtual
> stack tracks slot loads, not the pushed values; frame nodes take a byte offset from the frame base;
> and a parameter slot is frame storage (`argN`) only while it still holds the caller's value - a
> value pushed there after the function popped the parameter is an ordinary stack slot. The current
> behavior is documented in `ir/llil/llil_builder.py`, `falcom/ed9/ir/llil/llil_builder.py` and
> `docs/`. A full rewrite of this file is pending.

> 版本：draft
> 说明：本文件是 **Falcom_LLIL 方言** 的规范，约束 Falcom VM 在使用 Core LLIL 时的栈 / SP / 调用等行为。

---

## 0. 分层与适用范围（Core LLIL vs Falcom_LLIL）

本规范描述的是 **Falcom VM 在使用 LLIL 时的约束与习惯用法（Falcom_LLIL dialect）**，
而不是整个项目中“通用 LLIL（Core LLIL）”的完整定义。两者分层关系如下：

### 0.1 Core LLIL（通用层）

- Core LLIL 是项目中最基础、可复用的一层 IR：
  - 提供通用的指令类型与基本语义，例如：
    - `LowLevelILInstruction / LowLevelILExpr / LowLevelILStatement`
    - 常量与算术：`Const* / BinaryOp / UnaryOp / Compare / TestZero` 等
    - 寄存器：`Reg / SetReg`
    - 内存 / 虚拟堆访问：`Load / Store` 或类似原语
    - 控制流：`If / Goto / Call / Ret / Label / Nop` 等
    - （可选）栈原语：`StackLoad / StackStore / SpAdd` 等
  - Core LLIL **不规定**：
    - 具体 VM 的调用约定（cdecl/stdcall 等）
    - 函数入口 / 退出时的 `SP` 值
    - 参数 / 局部变量如何布局到栈 / 帧
    - 各 VM 在翻译阶段必须采用哪种栈纪律

- 换言之：**Core LLIL 只定义“能做什么”，不约束“各 VM 必须怎么用”。**

### 0.2 Falcom_LLIL（Falcom 专用方言）

- 本文件（`falcom_llil_spec.md`）描述的是：
  - 在 Falcom VM 的前端 / 翻译中，**允许如何使用 Core LLIL**；
  - 以及 Falcom VM 对栈、`SP`、帧（frame）、vstack 等的具体约束。
- 例如，本规范中的约定：
  - `SP` 只能通过 `LowLevelILSpAdd` 改变；
  - Frame 区使用绝对 slot 访问（`FrameLoad/FrameStore(slot)`）；
  - Falcom 函数入口 `SP = frame_size`，退出时通过 `SpAdd(-frame_size)` 使 `SP = 0`（stdcall 风格）；
  - 规范化 IR 中只能使用 `StackLoad/StackStore/SpAdd` 作为栈原语，`StackPush/StackPop` 仅限于 builder 语法糖等。
- 这些规则只对 **Falcom_LLIL** 生效：
  - 用于约束 Falcom VM 的翻译器 / 分析 pass；
  - 不强制其他 VM 或前端也采用相同栈布局与调用约定。

### 0.3 后续扩展的约定

- 若未来引入其他 VM（例如 `xxx_vm`），应当：
  - 复用 Core LLIL 的指令与基本语义；
  - 为该 VM 单独编写 `xxx_llil_spec.md`，定义其专用栈纪律 / 调用约定 / 特有指令等。
- Falcom_LLIL 相关的规则（本文件）仅描述 Falcom 这一种 VM 的“家规”，
  Core LLIL 仍保持为相对中立、可扩展的基础层。

---

## 1. Expr / Statement、vstack 与 Basic Block

### 1.1 类型分层约定

- 所有 LLIL 节点共有基类：

  ```python
  class LowLevelILInstruction(ABC):
      operation: LowLevelILOperation
      address: int
      inst_index: int  # 由 LowLevelILFunction 分配
  ```

- 在其基础上分为两类：

  ```python
  class LowLevelILExpr(LowLevelILInstruction):
      pass  # 有值，可作为操作数，可入 vstack

  class LowLevelILStatement(LowLevelILInstruction):
      pass  # 无值，仅表示副作用
  ```

- 约束：
  - Expr：表示“值”，可被其他 Expr 使用。
  - Statement：表示副作用（写寄存器/内存/控制流等），**不能**进 vstack。

### 1.2 vstack 约定

- vstack 是 builder 的计算栈，只在构建 LLIL 时使用。
- 不允许任何 `LowLevelILStatement` 进入 vstack。

不变式：

- vstack 内元素类型：**只允许 `LowLevelILExpr`**。

  ```python
  def vstack_push(expr: LowLevelILExpr): ...
  def vstack_pop() -> LowLevelILExpr: ...
  def vstack_peek() -> LowLevelILExpr: ...
  ```

### 1.3 Basic Block 约定

- basic block 仅存放 Statement：

  ```python
  class LowLevelILBasicBlock:
      statements: list[LowLevelILStatement]
  ```

- Expr 不直接存入 basic block，仅作为：
  - Statement 的子节点；
  - builder 内部 vstack 的元素。

不变式：

- `add_instruction()` / `append()` 等接口参数必须是 `LowLevelILStatement`。
- 若某个值需要在 IR 中持久化，应：
  1. 用 Expr 描述值本身；
  2. 再用 Statement 把该值写到寄存器/栈槽/全局。

### 1.4 指令索引与查询

- basic block 将指令加入函数时，`LowLevelILFunction` 会分配全局唯一的 `inst_index`（初始值为 -1）。
- 如果某条指令已经被使用（`inst_index != -1`）却再次加入 block，`LowLevelILBasicBlock.add_instruction()` 会抛出 `RuntimeError`。
- 可用的查询接口：
  - `get_instruction_by_index(idx)`：根据 `inst_index` 获取指令对象
  - `get_instruction_block_by_index(idx)`：获取指令所在的 basic block
  - `iter_instructions()`：按插入顺序遍历函数内所有指令

### 1.5 终结指令基类（Terminal）

```python
class LowLevelILTerminal(LowLevelILStatement):
    pass  # 终结一个 basic block 的指令基类
```

所有能终结 basic block 的指令必须继承 `LowLevelILTerminal`。
当前 Falcom_LLIL 中至少包含：

```python
class LowLevelILRet(LowLevelILTerminal):
    pass

class LowLevelILCall(LowLevelILTerminal):
    target_func: LowLevelILExpr
    ret_func: LowLevelILExpr
    ret_block: LowLevelILBasicBlock

class LowLevelILGoto(LowLevelILTerminal):
    target_block: LowLevelILBasicBlock

class LowLevelILIf(LowLevelILTerminal):
    condition: LowLevelILExpr
    true_block: LowLevelILBasicBlock
    false_block: LowLevelILBasicBlock
```

语义约定：

- `LowLevelILGoto`：
  - 无条件跳转到 `target_block`；
  - 不得修改 `sp`。

- `LowLevelILIf`：
  - 计算 `condition`：
    - 非零视为 true，跳转到 `true_block`；
    - 零视为 false，跳转到 `false_block`；
  - 不得修改 `sp`。

Basic Block 约束：

- 对每个 `LowLevelILBasicBlock`：
  - `statements` 中 **最多出现一个** `LowLevelILTerminal`；
  - 若存在 `LowLevelILTerminal`，则它必须是最后一条指令；
  - 不允许在 `LowLevelILTerminal` 之后再追加任何指令。

builder 约定：

- 若当前 block 已经包含 `LowLevelILTerminal`，再次追加指令属于错误；
- 若追加的是 `LowLevelILTerminal`，之后禁止再向该 block 追加任何指令。

与栈 / vstack 的关系：

- `Goto` / `If` 本身不读写栈：
  - 不生成 `LowLevelILStackLoad/Store`；
  - 不生成 `LowLevelILSpAdd`。
- 如需基于栈顶或其他值分支，由 VM→Falcom_LLIL lifter 在 `If` 之前显式生成相应的栈/寄存器操作，使 `condition` 成为一个普通 `LowLevelILExpr`。

---

## 2. SP（栈指针）操作规范

### 2.1 总约定

> 在 Falcom_LLIL 中，**`sp` 的改变只能由 `LowLevelILSpAdd` 表达**。
> builder 不得“只改影子 sp 而不 emit `LowLevelILSpAdd`”。

- IR 中所有对 `sp` 的增减，必须显式出现为一条 `LowLevelILSpAdd`。
- 只在 builder 内部改 `sp` 变量而不生成 `SpAdd` 的行为是非法的。

### 2.2 `LowLevelILSpAdd` 语义

```python
class LowLevelILSpAdd(LowLevelILStatement):
    delta: int  # 允许正负
    # 语义：sp = sp + delta
```

- `delta > 0`：栈向“上”增长（push 后）。
- `delta < 0`：栈向“下”收缩（pop 前）。

### 2.3 builder 影子 sp

- builder 可以维护影子 sp（compile-time helper），例如：

  ```python
  self._sp_offset  # 当前函数内逻辑 sp 值
  ```

- 影子 sp 只用于：
  - 计算 `StackLoad/Store` 的 offset；
  - 断言/调试；
  - 计算 slot_index 等。
- 影子 sp 不代表 IR 语义，语义仅由 IR 中的 `LowLevelILSpAdd` 决定。

允许写法：

```python
def sp_add(self, delta: int) -> LowLevelILSpAdd:
    inst = LowLevelILSpAdd(delta)
    self.add_instruction(inst)
    self._sp_offset += delta
    return inst
```

不允许写法示例：

```python
def sp_adjust(self, delta: int):
    # ❌ 只改影子 sp，不 emit SpAdd —— 违反约定
    self._sp_offset += delta
```

### 2.4 栈访问指令（不改 sp）

```python
class LowLevelILStackLoad(LowLevelILExpr):
    offset: int
    # 语义：result = STACK[sp + offset]

class LowLevelILStackStore(LowLevelILStatement):
    offset: int
    value: LowLevelILExpr
    # 语义：STACK[sp + offset] = value

class LowLevelILFrameLoad(LowLevelILExpr):
    slot: int
    # 语义：result = FRAME[slot]

class LowLevelILFrameStore(LowLevelILStatement):
    slot: int
    value: LowLevelILExpr
    # 语义：FRAME[slot] = value
```

- 上述四类指令本身都不改变 `sp`。
- 需要移动 `sp` 时，必须额外发 `LowLevelILSpAdd`。

### 2.5 push / pop 模板（Falcom_LLIL builder）

push：

```python
def push(self, value: LowLevelILExpr) -> LowLevelILExpr:
    # 1) 写当前栈顶 slot
    store = LowLevelILStackStore(offset=0, value=value)
    self.add_instruction(store)
    # 2) sp = sp + 1
    self.sp_add(+1)
    # 3) vstack 记录
    self.vstack_push(value)
    return value
```

pop：

```python
def pop(self) -> LowLevelILExpr:
    if self.vstack_size() > 0:
        self.vstack_pop()

    # 1) sp = sp - 1
    self.sp_add(-1)
    # 2) 读新的栈顶
    load = LowLevelILStackLoad(offset=0)
    return load
```

不变式：

- push：`StackStore(sp+0, value)` → `SpAdd(+1)`
- pop：`SpAdd(-1)` → `StackLoad(sp+0)`

### 2.6 检查表（指令级）

- [x] vstack 里只存 `LowLevelILExpr`。
- [x] basic block 里只存 `LowLevelILStatement`。
- [x] 所有 `sp` 变化对应 `LowLevelILSpAdd`。
- [x] 修改影子 sp 时必须同时 emit `LowLevelILSpAdd`。
- [x] `StackLoad/Store` / `FrameLoad/Store` 不改变 `sp`。
- [x] push/pop 形式符合：
  - push：`StackStore(sp+0, value)` → `SpAdd(+1)`
  - pop：`SpAdd(-1)` → `StackLoad(sp+0)`

---

## 3. 函数栈布局与调用约定（stdcall 风格）

### 3.1 单一逻辑栈与 FP

- 每个函数只有一条逻辑栈：`STACK[0], STACK[1], ...`。
- 定义逻辑帧指针 FP = 0（不作为显式寄存器出现）：
  - `FrameLoad/FrameStore(slot)` 语义等价于访问 `STACK[slot]`。

### 3.2 frame_size 与入口 SP

- 对每个函数，定义 `frame_size >= 0`：
  - 包含所有参数和（如有）入口即占位的固定局部变量。
  - 对应 `STACK[0 .. frame_size-1]`。
- 函数入口：

  ```text
  SP(entry) = frame_size
  ```

### 3.3 Eval 栈（运算栈）

- Frame 区之外的栈空间作为 Eval 栈，用于中间值。
- 通过 `StackLoad/StackStore` + `SpAdd` 管理。

### 3.4 入口 / 退出不变量

每个函数：

```text
入口： SP = frame_size
退出前：SP 必须回到 frame_size（Eval 栈清空）
退出时：SpAdd(-frame_size) 使 SP = 0，然后 Ret
```

即 callee 负责清理自身 frame（stdcall 风格）。

---

## 4. 栈原语与规范化要求

- 规范化后的 Falcom_LLIL 中栈原语限定为：
  - `LowLevelILStackLoad`
  - `LowLevelILStackStore`
  - `LowLevelILSpAdd`
- 不允许出现 `LowLevelILStackPush` / `LowLevelILStackPop`，若有须在 normalize pass 中展开为上述三者组合。

---

## 5. 返回值与返回寄存器

- 返回值统一通过 `reg(0)` 传递。
- `LowLevelILRet` 不带 Expr，表示“按当前 `reg(0)` 返回”。

```python
class LowLevelILReg(LowLevelILExpr):
    reg: RegisterID  # 包括 0

class LowLevelILSetReg(LowLevelILStatement):
    reg: RegisterID
    value: LowLevelILExpr

class LowLevelILRet(LowLevelILTerminal):
    pass  # 返回，使用当前 reg(0) 作为函数结果（若有）
```

- VM opcode 若需使用返回值，其 LLIL 转换须显式生成 `LowLevelILReg(0)`。

---

## 6. 调用指令（Falcom_LLIL）

### 6.1 VM 层调用模式

```text
PUSH_CURRENT_FUNC_ID()
PUSH_RET_ADDR(<ret_label>)
[PUSH_* ...]          ; 任意数量的普通 PUSH（参数 / 中间值等）
CALL(<target_func>)
```

- `PUSH_CURRENT_FUNC_ID()`：压入当前函数 ID。
- `PUSH_RET_ADDR(<ret_label>)`：压入返回地址 `<ret_label>`。
- 中间的 `PUSH_*` 为普通 PUSH 指令（由各自规则翻译）。
- `RET` 时 VM 自动弹出返回信息（无显式 POP）。

### 6.2 `LowLevelILCall` 结构

```python
class LowLevelILCall(LowLevelILTerminal):
    target_func: LowLevelILExpr         # 被调函数
    ret_func: LowLevelILExpr            # 返回函数 ID
    ret_block: LowLevelILBasicBlock     # 返回 basic block
```

约束：

- `LowLevelILCall` 本身 **不得修改 `sp`**。

### 6.3 VM → Falcom_LLIL 转换规则

- VM 解析阶段已根据函数入口、`<ret_label>`、显式跳转等划分 basic block。

遇到以下指令时：

1. `PUSH_CURRENT_FUNC_ID()`
   - 生成栈访问指令；
   - 仅产生一个表达式 `ret_func_expr`，供后续 `LowLevelILCall.ret_func` 使用。

2. `PUSH_RET_ADDR(<ret_label>)`
   - `<ret_label>` 对应 basic block 记为 `ret_block`；
   - 生成栈访问指令；
   - 供后续 `LowLevelILCall.ret_block` 使用。

3. 其它所有 `PUSH_*` 指令（包括位于 `PUSH_RET_ADDR` 与 `CALL` 之间的指令）
   - 一律按普通栈操作翻译为：

     ```text
     StackStore(SP + 0, <value_expr>)
     SpAdd(+1)
     ```

4. `CALL(<target_func>)`
   - 生成一条调用指令：

     ```python
     LowLevelILCall(
         target_func = target_func_expr,
         ret_func    = ret_func_expr,   # 来自最近一次 PUSH_CURRENT_FUNC_ID
         ret_block   = ret_block,       # 来自最近一次 PUSH_RET_ADDR
     )
     ```

   - `LowLevelILCall` 本身不产生对 `sp` 的修改。

### 6.4 与栈 / 返回值的关系

- 栈与 `sp`：
  - Falcom_LLIL 层的 `sp` 仅描述脚本可见的数据栈；
  - `PUSH_CURRENT_FUNC_ID` / `PUSH_RET_ADDR` 不转换为 `StackStore/SpAdd`，不影响 Falcom_LLIL 的 `sp`；
  - 其它所有 `PUSH_*` 统一生成 `StackStore(SP+0, ...) + SpAdd(+1)`；
  - 当前函数内 `sp` 的变化必须全部由显式 `LowLevelILSpAdd` 表达。

- 返回值：
  - 函数返回值统一通过 `reg(0)` 传递；
  - `LowLevelILCall` 不携带返回值表达式；
  - 需要使用返回值的 VM opcode 在对应的 LLIL 转换中显式生成 `LowLevelILReg(0)`。
