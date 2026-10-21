"""ecdet —— 嵌入式软件代码缺陷与安全漏洞检测系统。

按技术方案 V1.0 的五层架构组织：
  L1 编译环境复现层（ecdet.l1_build）      —— 解决 P1：产出 compile_commands.json
  L2 统一 IR / 程序表示层（ecdet.l2_ir）   —— 统一告警数据模型与 SARIF 交换格式
  L3 多引擎分析层（ecdet.l3_analysis）     —— 规则引擎 / 外部引擎适配，硬件语义注入点
  L4 LLM 增强层（ecdet.l4_llm）            —— 告警分诊 / 误报过滤 / 修复建议（阶段三）
  L5 结果聚合与可证明性输出层（ecdet.l5_report） —— 去重、CWE/MISRA 映射、合规报告
"""

__version__ = "0.7.0"
