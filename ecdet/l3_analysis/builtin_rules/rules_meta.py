"""内置规则元数据库 —— 阶段一 MVP + 2026-11 规则缺口核验批次。

三集管理与行业裁剪依据技术方案 3.3.3：
  - MISRA C:2012 子集（句法可判类优先）
  - CERT C 子集（与 CWE 官方映射对齐）
  - ECDET 自有缺陷规则（以 CWE 编号命名，双口径输出）
每条规则标注可判定性（decidability），供 L4 LLM 分诊与人工评审路由。

2026-11 批次依据《规则缺口清单_20261102.xlsx》逐条核验（结论见
《规则核验与去重对照表_20261103.xlsx》），仅补入"确认缺失且当前
token 级基础设施可判定"的规则；需 SVD/位域布局/整工程类型系统
支撑的候选规则保留在对照表"待条件落地"栏。编号勘误同步修正：
  - goto 禁令 → 15.1；15.2 改为"仅允许前向同函数跳转"
  - 宏参数括号 → 20.7；PRE31-C 改为"宏参数不得含副作用"
  - atoi 等转换函数 → 21.7；终止函数 → 21.8（malloc 仍为 21.3）
  - 全局变量 static 化 → 8.7；8.9 改为"单函数使用的对象应在块作用域"
"""

from __future__ import annotations

from ecdet.l2_ir.model import RuleMeta

MISRA = "MISRA C:2012"
CERT = "CERT C"
ECDET = "ECDET"

BUILTIN_RULES: list[RuleMeta] = [
    # ---------------- MISRA C:2012 ----------------
    RuleMeta("MISRA C:2012 2.5", MISRA, "Advisory", "syntactic",
             "宏已定义但在翻译单元中未被使用", []),
    RuleMeta("MISRA C:2012 7.2", MISRA, "Required", "syntactic",
             "无符号类型的整型常量表达式应带 u/U 后缀",
             ["CWE-681"]),
    RuleMeta("MISRA C:2012 8.7", MISRA, "Required", "project",
             "仅被单个翻译单元引用的函数或对象应具有内部链接（static）",
             []),
    RuleMeta("MISRA C:2012 8.9", MISRA, "Advisory", "project",
             "仅在单个函数中使用的对象应在块作用域定义",
             []),
    RuleMeta("MISRA C:2012 8.5", MISRA, "Required", "project",
             "外部对象或函数应只在一个文件中定义/声明",
             []),
    RuleMeta("MISRA C:2012 10.3", MISRA, "Required", "type-based",
             "赋值表达式的值不应发生基本类型类别降级（秩收窄或符号性改变）",
             ["CWE-197", "CWE-190"]),
    RuleMeta("MISRA C:2012 10.4", MISRA, "Required", "type-based",
             "常规算术转换双操作数的基本类型类别应一致（禁止符号性混算）",
             ["CWE-190"]),
    RuleMeta("MISRA C:2012 13.5", MISRA, "Required", "syntactic",
             "逻辑 && 与 || 的右操作数不应包含持续副作用（自增/赋值/函数调用）",
             ["CWE-784"]),
    RuleMeta("MISRA C:2012 14.2", MISRA, "Required", "syntactic",
             "for 循环计数变量不应在循环体内被修改",
             ["CWE-834"]),
    RuleMeta("MISRA C:2012 15.1", MISRA, "Advisory", "syntactic",
             "不应使用 goto", ["CWE-670"]),
    RuleMeta("MISRA C:2012 15.2", MISRA, "Required", "syntactic",
             "goto 只能跳转到同一函数内之后定义的标签", ["CWE-670"]),
    RuleMeta("MISRA C:2012 15.5", MISRA, "Advisory", "syntactic",
             "函数末尾应有单一退出点（return 不应多于一个）", []),
    RuleMeta("MISRA C:2012 16.4", MISRA, "Required", "syntactic",
             "每个 switch 语句应具有 default 标签", []),
    RuleMeta("MISRA C:2012 16.6", MISRA, "Required", "syntactic",
             "每个 switch 语句应至少包含两个 case 标签", []),
    RuleMeta("MISRA C:2012 17.2", MISRA, "Required", "syntactic",
             "不应使用递归（栈深不可控，强实时场景资源风险）",
             ["CWE-674"]),
    RuleMeta("MISRA C:2012 17.3", MISRA, "Mandatory", "project",
             "不应隐式声明函数（调用前无可见原型）",
             ["CWE-758"]),
    RuleMeta("MISRA C:2012 21.1", MISRA, "Required", "syntactic",
             "不应定义或使用保留标识符（下划线开头大写/含双下划线）",
             ["CWE-709"]),
    RuleMeta("MISRA C:2012 21.3", MISRA, "Required", "syntactic",
             "不得使用 stdlib.h 的内存分配与释放函数（malloc/calloc/realloc/free）",
             ["CWE-676"]),
    RuleMeta("MISRA C:2012 21.7", MISRA, "Required", "syntactic",
             "不得使用字符串转换函数 atof/atoi/atol/atoll",
             ["CWE-190"]),
    RuleMeta("MISRA C:2012 21.8", MISRA, "Required", "syntactic",
             "不得使用进程终止函数 abort/exit/atexit/_Exit/quick_exit",
             ["CWE-676"]),
    RuleMeta("MISRA C:2012 21.9", MISRA, "Required", "syntactic",
             "不得使用 bsearch/qsort 库函数",
             ["CWE-676"]),
    RuleMeta("MISRA C:2012 21.10", MISRA, "Required", "syntactic",
             "不得使用 getenv 库函数",
             ["CWE-676"]),
    RuleMeta("MISRA C:2012 21.6", MISRA, "Required", "syntactic",
             "不得使用 stdio.h 的输入/输出库函数（嵌入式场景 I/O 库禁用）",
             ["CWE-676"]),
    # ---------------- CERT C ----------------
    RuleMeta("MISRA C:2012 20.7", MISRA, "Required", "syntactic",
             "宏参数在宏体中每次出现都应加括号，防止运算符优先级破坏",
             ["CWE-783"]),
    RuleMeta("CERT C PRE31-C", CERT, "Required", "syntactic",
             "不得向会多次求值参数的宏传递含副作用的实参",
             ["CWE-480"]),
    RuleMeta("CERT C MSC30-C", CERT, "Required", "syntactic",
             "不得使用 rand() 生成安全相关随机数（应使用硬件 RNG）",
             ["CWE-338", "CWE-337"]),
    RuleMeta("CERT C STR31-C", CERT, "Required", "syntactic",
             "字符串/内存拷贝必须保证目标存储空间充足（常量长度核对）",
             ["CWE-120", "CWE-787"]),
    RuleMeta("CERT C ARR30-C", CERT, "Required", "syntactic",
             "不得以常量下标访问数组越界位置",
             ["CWE-125", "CWE-787"]),
    RuleMeta("CERT C FIO30-C", CERT, "Required", "syntactic",
             "格式化 I/O 函数的格式串必须是字面量，排除外部可控格式串",
             ["CWE-134"]),
    # ---------------- ECDET 自有缺陷规则（CWE 口径） ----------------
    RuleMeta("ECDET-CWE-242", ECDET, "Mandatory", "syntactic",
             "使用了 gets()——C11 已删除的无界读取函数，必然缓冲区溢出风险",
             ["CWE-242", "CWE-120"]),
    RuleMeta("ECDET-CWE-197", ECDET, "Mandatory", "syntactic",
             "整型字面量初始化超出定宽类型表示范围，发生数值截断",
             ["CWE-197", "CWE-190"]),
    RuleMeta("ECDET-CWE-1284", ECDET, "Required", "syntactic",
             "scanf 家族使用 %s 且未限定宽度，读取长度无界",
             ["CWE-1284", "CWE-120"]),
    RuleMeta("ECDET-CWE-563", ECDET, "Advisory", "syntactic",
             "函数参数在函数体内未被使用（未使用参数）",
             ["CWE-563"]),
    # ---------------- ECDET 硬件语义规则（阶段二，P2） ----------------
    RuleMeta("ECDET-MMIO-ACCESS", ECDET, "Mandatory", "dataflow",
             "违背 SVD 定义的 MMIO 寄存器访问权限（写只读/读写只寄存器）",
             []),
    RuleMeta("ECDET-MMIO-W1C", ECDET, "Required", "dataflow",
             "对写1清零寄存器进行读改写，可能误清除其他状态位",
             []),
    RuleMeta("ECDET-ISR-RACE", ECDET, "Required", "dataflow",
             "ISR 与任务上下文共享全局变量且访问侧无临界区保护",
             ["CWE-362", "CWE-667"]),
    RuleMeta("ECDET-VOLATILE", ECDET, "Advisory", "syntactic",
             "ISR 共享变量未声明 volatile，编译器优化可能破坏跨上下文可见性",
             ["CWE-362"]),
    RuleMeta("ECDET-ISR-BLOCK", ECDET, "Mandatory", "syntactic",
             "ISR 中调用阻塞/非 FromISR 安全的 RTOS API",
             ["CWE-676"],
             properties={"aliases": ["ECDET-HW-FROMISR"]}),
    # ---------------- 2026-11 缺口核验批次：MISRA ----------------
    RuleMeta("MISRA C:2012 2.1", MISRA, "Advisory", "syntactic",
             "不应存在不可达代码", ["CWE-561"]),
    RuleMeta("MISRA C:2012 6.1", MISRA, "Required", "type-based",
             "位域应具有 _Bool、signed int、unsigned int 或实现定义类型",
             ["CWE-197"]),
    RuleMeta("MISRA C:2012 11.3", MISRA, "Required", "type-based",
             "不得在指向不同对象类型的指针之间强制转换", ["CWE-704"]),
    RuleMeta("MISRA C:2012 11.4", MISRA, "Required", "type-based",
             "不得在指向对象的指针与整数之间强制转换", ["CWE-704"]),
    RuleMeta("MISRA C:2012 11.8", MISRA, "Required", "type-based",
             "不得移除指向类型的 const/volatile 限定", ["CWE-704"]),
    RuleMeta("MISRA C:2012 12.2", MISRA, "Required", "type-based",
             "移位右操作数应在 0 到左操作数位宽减一之间", ["CWE-682"]),
    RuleMeta("MISRA C:2012 13.6", MISRA, "Required", "syntactic",
             "sizeof 的操作数不得包含副作用表达式", ["CWE-758"]),
    RuleMeta("MISRA C:2012 14.3", MISRA, "Required", "syntactic",
             "控制表达式不得为不变量（常量条件）", ["CWE-570"]),
    RuleMeta("MISRA C:2012 16.3", MISRA, "Required", "syntactic",
             "每个 switch 子句应以无条件 break 终止", ["CWE-484"]),
    RuleMeta("MISRA C:2012 18.6", MISRA, "Required", "dataflow",
             "不得将指向自动存储对象的指针传递到其作用域之外", ["CWE-562"]),
    RuleMeta("MISRA C:2012 18.8", MISRA, "Required", "syntactic",
             "不得使用可变长度数组类型（VLA）", ["CWE-770"]),
    RuleMeta("MISRA C:2012 20.8", MISRA, "Required", "syntactic",
             "#if/#elif 控制表达式应求值为 0 或 1", ["CWE-758"]),
    RuleMeta("MISRA C:2012 20.10", MISRA, "Required", "syntactic",
             "不得使用 # 或 ## 预处理运算符", ["CWE-758"]),
    RuleMeta("MISRA C:2012 21.17", MISRA, "Required", "syntactic",
             "不得使用长度不受约束的字符串/内存函数", ["CWE-120"]),
    # ---------------- 2026-11 缺口核验批次：CERT ----------------
    RuleMeta("CERT C INT30-C", CERT, "Required", "type-based",
             "无符号整数运算不得回绕", ["CWE-190"]),
    RuleMeta("CERT C INT32-C", CERT, "Required", "type-based",
             "有符号整数运算不得溢出", ["CWE-190"]),
    RuleMeta("CERT C INT34-C", CERT, "Required", "type-based",
             "不得以负数或超过操作数位宽的值移位", ["CWE-682"]),
    RuleMeta("CERT C INT36-C", CERT, "Required", "type-based",
             "不得将指针转换为整数", ["CWE-704"]),
    RuleMeta("CERT C EXP45-C", CERT, "Required", "syntactic",
             "控制表达式中不得出现赋值运算", ["CWE-480"]),
    RuleMeta("CERT C MEM34-C", CERT, "Required", "syntactic",
             "不得释放非动态分配的内存", ["CWE-590"]),
    RuleMeta("CERT C MSC41-C", CERT, "Required", "syntactic",
             "不得在源码中硬编码口令/密钥等敏感信息", ["CWE-798"]),
    # ---------------- 2026-11 缺口核验批次：ECDET ----------------
    RuleMeta("ECDET-CWE-190", ECDET, "Required", "syntactic",
             "常量算术表达式发生有符号溢出或无符号回绕", ["CWE-190"]),
    RuleMeta("ECDET-CWE-785", ECDET, "Required", "syntactic",
             "函数内大对象占用栈空间过大，存在栈溢出风险", ["CWE-785"]),
    RuleMeta("ECDET-CWE-78", ECDET, "Mandatory", "syntactic",
             "调用 system() 执行外部命令，存在命令注入风险", ["CWE-78"]),
    RuleMeta("ECDET-HW-CRITICAL-PAIR", ECDET, "Required", "dataflow",
             "临界区进入/退出宏未配对，可能长期关闭中断", ["CWE-667"]),
    RuleMeta("ECDET-HW-ISR-HEAP", ECDET, "Mandatory", "syntactic",
             "ISR 中调用非 async-safe 函数（堆分配/stdio 等）", ["CWE-676"]),
    RuleMeta("ECDET-HW-VOLATILE-RMW", ECDET, "Required", "dataflow",
             "volatile 共享变量的自增/复合赋值在临界区外执行，非原子",
             ["CWE-362"]),
    RuleMeta("ECDET-HW-BITFIELD", ECDET, "Advisory", "syntactic",
             "位域赋值超出声明位宽", ["CWE-197"]),
]

# 规则别名（缺口清单编号 / 历史编号 → 当前规范编号），供启停配置与报告追溯
RULE_ALIASES: dict[str, str] = {
    "ECDET-HW-FROMISR": "ECDET-ISR-BLOCK",
}

_RULES_INDEX = {r.rule_id: r for r in BUILTIN_RULES}


def canonical_rule_id(rule_id: str) -> str:
    """别名归一为当前规范规则编号。"""
    return RULE_ALIASES.get(rule_id, rule_id)


def get_rule_meta(rule_id: str) -> RuleMeta | None:
    return _RULES_INDEX.get(canonical_rule_id(rule_id))
