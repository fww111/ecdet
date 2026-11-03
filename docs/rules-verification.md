# 规则缺口核验与去重说明（2026-11）

对应 [issue #1](https://github.com/fww111/ecdet/issues/1)：核验《规则缺口清单_20261102.xlsx》候选规则，与现有检测能力去重，补入确认可用且有新增覆盖价值的规则。

## 1. 结论摘要

- 核验对象：优先补全清单 **63 项**（P0 26 / P1 37），另核对 309 项全量索引的标准映射与重复关系；全量索引不作为逐条实现目标。
- 首轮结论：**已覆盖 7 / 部分覆盖 23 / 确认缺失 26 / 暂无法确认 7**。
- 本批落地：新增自研规则 **25 条**（含 P0 12 条），扩展 3 条既有实现，修正 5 处编号/语义勘误与 3 类映射错误。内置规则从 30 条增至 **65 条**（MISRA 38 / CERT 12 / ECDET 15，其中硬件语义 8 条）。
- 去重口径：规则库层面保留标准映射与多来源；运行告警层面只按**显式等价组**合并，不再仅凭同一 CWE 泛化合并。
- 未落地项与前置条件见第 6 节；CodeChecker 原生检查器的“实际启用”仍需运行级 `manifest.json` 实测确认，本文不把目录存在等同于覆盖。

逐条对照表（63 项核验、重复关系、勘误、覆盖口径）随 PR 提交：`调研/规则核验与去重对照表_20261103.xlsx`。

## 2. 判定口径

| 维度 | 口径 |
| --- | --- |
| 标准编号 | 以 MISRA C:2012 / SEI CERT C 规则标题与条款语义为准，编号错配按勘误处理 |
| “已覆盖” | 既有自研规则、硬件语义、抽象解释或 CodeChecker 原生检查器**实际调度**且检测范围一致 |
| “部分覆盖” | 检测场景少于条款要求，或仅有邻近语义；复用并补齐剩余场景 |
| “确认缺失” | 无任何现有实现覆盖，按 token/类型/工程层可实现性分批补充 |
| “暂无法确认” | 依赖运行级 manifest、编译参数或外部上下文，未实测前不下结论 |
| 覆盖统计 | 标准条款数、检测实现数（rule_id）、实际启用数**分列**，禁止用旧“59 条”口径推算覆盖率 |

## 3. 编号与映射勘误（已验证后修正）

| 原表述 | 修正 | 依据 |
| --- | --- | --- |
| 21.3 = 禁用 atoi/atof 等 | 21.3 仅内存分配/释放（`malloc/calloc/realloc/free`）；`atof/atoi/atol/atoll` 归 **21.7** | MISRA C:2012 Rule 21.3 / 21.7 headline |
| 15.2 = 禁用 goto | 禁用 goto 为 **15.1**（Advisory）；**15.2** 为“goto 只能跳到同一函数内之后声明的标签” | Rule 15.1 / 15.2 headline |
| 8.9 = 单文件引用全局变量加 static | 该语义属 **8.7**（函数与对象内部链接）；**8.9** 为“仅在单个函数中使用的对象应定义在块作用域” | Rule 8.7 / 8.9 headline |
| PRE31-C = 宏参数必须加括号 | 宏参数加括号为 **20.7**；**PRE31-C** 为“宏实参不得含副作用” | CERT PRE31-C 标题 + Rule 20.7 headline |
| 空指针条目使用 CWE-477 | 空指针解引用为 **CWE-476**（CWE-477 是使用过时函数） | CWE 官方条目 |

映射表 `ecdet/rules_db/cwe_map.json` 同步修正：

- CWE-120 → MISRA 21.17 / 21.18（不再映射到 21.3）；
- 移除 CWE-338 与 21.3 的错误映射；
- 补齐 CWE-125/190/197/362/667/704/682/562/770/484/480/590/798/783/570/670/785/78/561 等条目。

规则别名保持可追溯：`ECDET-HW-FROMISR` → `ECDET-ISR-BLOCK`（`RULE_ALIASES` + `canonical_rule_id`，profile/启停均按规范 ID 归一）。

## 4. 本批新增与扩展

新增实现位于 `ecdet/l3_analysis/builtin_rules/checks_verified.py` 与 `hw_model/checks_hw.py`，注册到既有 `FILE_RULES` / `PROJECT_RULES` / `HW_RULES` 调度，不另建平行引擎。

### 4.1 通用规则（token / 声明 / 工程层）

| 规则 | 检测语义 | 判定边界 |
| --- | --- | --- |
| MISRA 2.1 | `return` 之后同块内仍有语句 | 仅无条件 return；标签与 else 分支不报 |
| MISRA 6.1 | 位域类型不为 `_Bool/signed int/unsigned int`（或 32 位 typedef） | 逐行声明扫描 |
| MISRA 11.3 | 不同对象类型指针显式转换 | 仅“已声明标识符 + 直接 cast”；`void*` 除外 |
| MISRA 11.4 / CERT INT36-C | 指针与整数显式互转 | 同上；不做别名传播 |
| MISRA 11.8 | 强制转换移除 const/volatile 限定 | 源限定符来自参数/声明文本 |
| MISRA 12.2 / CERT INT34-C | 移位计数为负或 ≥ 左操作数位宽 | 常量、宏常量与已声明变量位宽 |
| MISRA 13.6 | `sizeof` 操作数含副作用 | 复用 13.5 副作用运算符集合 |
| MISRA 14.3 | if/while/for 条件为单一常量 | 不折叠变量与宏表达式 |
| MISRA 16.3 | switch 子句缺少无条件 break/return | 空子句（标签分组）不单独报 |
| MISRA 18.6 | `return &局部对象` | 仅直接取地址返回；跨函数存储待数据流 |
| MISRA 18.8 | 可变长度数组声明 | 常量/`sizeof`/全大写宏维度不报 |
| MISRA 20.8 | 纯数字 `#if/#elif` 求值不在 {0,1} | 含宏或逻辑运算符的表达式不求值 |
| MISRA 20.10 | 宏体使用 `#` / `##` | 预处理行扫描 |
| MISRA 21.17 | `memcpy/memmove` 常量长度超过源数组大小 | 越界读侧补充；目标侧由 STR31-C 覆盖 |
| CERT EXP45-C | if/while/for 条件含赋值 | 与编译器 `-Wparentheses` 互为补充 |
| CERT MEM34-C | `free` 取地址对象/数组/字符串字面量 | 仅直接实参形态 |
| CERT MSC41-C | 标识符含口令/密钥关键字且赋字符串常量 | 启发式，输出 Suspected |
| ECDET-CWE-190 / INT30-C / INT32-C | 相邻常量 `+ - *` 链溢出/回绕 | 仅常量链，跨宏/括号留给 Clang 常量传播 |
| ECDET-CWE-785 | 函数内数组栈占用 ≥ 1 KiB | 按元素类型估算，不做 sizeof 求值 |
| MISRA 8.5（工程层） | 外部对象/函数在多个 `.c` 文件重复定义 | 多文件工程；`main` 与 static 除外 |

### 4.2 硬件语义规则

| 规则 | 检测语义 | 前置条件 |
| --- | --- | --- |
| ECDET-ISR-BLOCK（扩展） | ISR 中不仅拦 `is_blocking`，也拦存在 FromISR 变体的非 FromISR 调用（如 `xSemaphoreGive`） | RTOS API 语义表 + ISR 命名/向量表识别 |
| ECDET-HW-CRITICAL-PAIR | 临界区 enter/exit 不成对或多余退出 | enter/exit 宏表 |
| ECDET-HW-ISR-HEAP | ISR 中调用非 async-safe 函数（堆、stdio、strtok、exit 等） | ISR 识别 + 黑名单 |
| ECDET-HW-VOLATILE-RMW | ISR 与任务共享的 volatile 变量在临界区外自增/复合赋值 | ISR/任务引用集 + 临界区行区间 |
| ECDET-HW-BITFIELD | 位域常量赋值超出声明位宽 | 位域声明扫描；输出 Suspected |

### 4.3 扩展既有实现

- `MISRA 8.7` 增加**对象**内部链接检查（原仅函数），`8.9` 改写为“单函数使用的对象应在块作用域”。
- `ECDET-ISR-BLOCK` 扩展 FromISR 等价对；保留旧 ID 别名。
- `ECTYPES.build_type_table` 跳过指针参数，修复 `char *p` 被当作整型导致 11.3 误判为 11.4 的问题。

## 5. 去重与聚合回归

- `aggregator._equivalence_classes` 改为基于 `cwe_map.json` 中显式 `equivalences` 的并查集；同 CWE 不同缺陷不再自动合并。
- 已声明等价组示例：`STR31-C ↔ CWE-120`、`ARR30-C ↔ CWE-787/CWE-125`、`11.4 ↔ INT36-C`、`12.2 ↔ INT34-C`、`ECDET-ISR-RACE ↔ ECDET-HW-VOLATILE-RMW`、`INT33-C ↔ ECDET-CWE-369`、`EXP34-C ↔ ECDET-CWE-476`。
- 回归用例：同位置等价规则合并为一簇；同位置同 CWE 但未声明等价（`STR31-C` 与 `21.17`）保持两簇。

## 6. 仍需条件落地的候选

| 候选 | 状态 | 缺失条件 |
| --- | --- | --- |
| ECDET-HW-PRIORITY | 未落地 | 需解析 `configMAX_SYSCALL_INTERRUPT_PRIORITY` 与 `NVIC_SetPriority` |
| ECDET-HW-RESERVED | 未落地 | 需 SVD 含 reserved 位/寄存器描述 |
| ECDET-HW-REG-SEQ | 未落地 | 需芯片手册或 SVD sequence 注记 |
| MISRA 18.1 / ARR36-C / ARR37-C | 暂无法确认 | 依赖 clang alpha `ArrayBoundV2` 实测与对象边界建模 |
| MISRA 21.18 | 未落地 | 需库函数长度实参与目标尺寸的契约表 |
| MISRA 9.1 / EXP33-C、CWE-476/EXP34-C | 复用 | `core.uninitialized.*`、`core.NullDereference`、Infer；需运行级 manifest 确认 |
| INT31-C、EXP32-C、EXP36-C、EXP39-C、EXP46-C | 复用/待实测 | 编译告警（`-Wconversion`/`-Wstrict-aliasing`）或类型/限定符溯源 |
| STR30-C、STR32-C、ARR38-C、MEM35-C | 未落地 | 需字符串终止符推理、对象边界与库函数契约 |
| SIG30-C / SIG31-C | 不适用/映射 | 嵌入式工程通常无 POSIX signal；ISR 语义由 ECDET-HW-ISR-HEAP / ECDET-ISR-RACE 承担 |
| MISRA 9.2 / 8.3 / 5.3 / 22.1 / 2.8 | 复用 | 编译器/Pppcheck 默认诊断；需实测启用参数 |
| EXP45-C | 已补充自研 | 与 `-Wparentheses` 并存，避免仅依赖编译参数 |

## 7. 启用与验证

```bash
uv run ecdet rules                                   # 查看 65 条规则与元数据
uv run pytest tests/test_rules.py tests/test_hw_model.py tests/test_l1_l2_l5.py
```

- 规则启停：`--enable` / `--disable` 接受规范 ID；`ECDET-HW-FROMISR` 等旧别名自动归一到规范规则。
- 测试覆盖：新增规则逐条提供应报样例与不应报样例（含边界：移位 `31`、位域宽度上限、memcpy 等长、固定长度数组、static 同名对象等）。
- 环境限制：`tests/test_cli_e2e.py` 依赖 CodeChecker 可执行文件，当前开发环境未安装时失败，不属本批代码回归。

## 8. 数据与证据

| 文件 | 内容 |
| --- | --- |
| `调研/规则缺口清单_20261102.xlsx` | 输入：63 项优先清单、309 项索引、覆盖统计、勘误建议 |
| `调研/规则核验与去重对照表_20261103.xlsx` | 交付：逐条核验、重复关系、勘误核验、覆盖口径与证据缺口 |
| `ecdet/rules_db/cwe_map.json` | CWE ↔ MISRA ↔ CERT 映射与显式等价组 |
| `ecdet/rules_db/gjb_map.json` | 新增规则的 GJB 8114 主题级映射（`verified=false`，编号待授权文本） |
