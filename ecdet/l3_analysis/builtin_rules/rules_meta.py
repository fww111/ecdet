"""内置规则元数据库 —— 阶段一 MVP 规则集（24 条）。

三集管理与行业裁剪依据技术方案 3.3.3：
  - MISRA C:2012 子集（句法可判类优先）
  - CERT C 子集（与 CWE 官方映射对齐）
  - ECDET 自有缺陷规则（以 CWE 编号命名，双口径输出）
每条规则标注可判定性（decidability），供 L4 LLM 分诊与人工评审路由。
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
             "仅被一个翻译单元引用的函数应具有内部链接（static）",
             []),
    RuleMeta("MISRA C:2012 8.9", MISRA, "Advisory", "project",
             "仅被一个翻译单元引用的全局变量应具有内部链接（static）",
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
    RuleMeta("MISRA C:2012 15.2", MISRA, "Required", "syntactic",
             "不应使用 goto", ["CWE-670"]),
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
             "不得使用 stdlib.h 的内存分配与转换函数（atof/atoi/atol/atoll 等）",
             ["CWE-190", "CWE-676"]),
    RuleMeta("MISRA C:2012 21.6", MISRA, "Required", "syntactic",
             "不得使用 stdio.h 的输入/输出库函数（嵌入式场景 I/O 库禁用）",
             ["CWE-676"]),
    # ---------------- CERT C ----------------
    RuleMeta("CERT C PRE31-C", CERT, "Required", "syntactic",
             "宏参数在宏体中每次出现都应加括号，防止运算符优先级破坏",
             ["CWE-789"]),
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
    RuleMeta("ECDET-ISR-RACE", ECDET, "Required", "dataflow",
             "ISR 与任务上下文共享全局变量且访问侧无临界区保护",
             ["CWE-362", "CWE-667"]),
    RuleMeta("ECDET-VOLATILE", ECDET, "Advisory", "syntactic",
             "ISR 共享变量未声明 volatile，编译器优化可能破坏跨上下文可见性",
             ["CWE-362"]),
    RuleMeta("ECDET-ISR-BLOCK", ECDET, "Mandatory", "syntactic",
             "ISR 中调用阻塞/非 FromISR 安全的 RTOS API",
             ["CWE-676"]),
]

_RULES_INDEX = {r.rule_id: r for r in BUILTIN_RULES}


def get_rule_meta(rule_id: str) -> RuleMeta | None:
    return _RULES_INDEX.get(rule_id)
