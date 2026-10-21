# ecdet —— 嵌入式软件代码缺陷与安全漏洞检测系统

面向汽车电子与工业控制场景的嵌入式 C/C++ 代码检测系统。依据《嵌入式软件代码缺陷与安全漏洞检测系统调研与技术方案》V1.0 实施，采用"规则与静态分析为骨架、LLM 增强的混合式"五层技术架构。

## 五层架构

| 层 | 模块 | 解决的问题 |
|----|------|-----------|
| L1 编译环境复现 | `ecdet.l1_build` | P1：任意嵌入式工程 → compile_commands.json |
| L2 统一表示 | `ecdet.l2_ir` | P3：多引擎输出统一为 SARIF 单一数据模型 |
| L3 多引擎分析 | `ecdet.l3_analysis` | P2/P4：自研规则引擎 + cppcheck/clang-tidy 适配 |
| L4 LLM 增强 | `ecdet.l4_llm` | P5：告警分诊/误报过滤/修复建议（阶段三） |
| L5 聚合与输出 | `ecdet.l5_report` | P3/P4：去重、CWE↔MISRA↔GJB 映射、可证明性分级、合规报告 |

## 快速开始

```bash
uv sync                                    # 安装（核心零第三方依赖）
uv run ecdet scan examples/demo_rtos       # 全量扫描（L1→L3→L5 一条龙）
uv run ecdet scan examples/demo_rtos --profile automotive
uv run ecdet init-ccdb path/to/project     # 仅 L1 构建复现
uv run ecdet rules                         # 查看规则集
uv run ecdet report results.sarif          # 从 SARIF 重新生成 HTML 报告
uv run pytest                              # 运行测试（57 项）
```

## Juliet 测试集接入（阶段一里程碑）

```bash
uv run python scripts/fetch_juliet.py --selftest            # 离线验证评测管线
uv run python scripts/fetch_juliet.py --download --limit 300  # 下载并评测检出率
```

## L4 LLM 告警分诊（阶段三，P5）

分诊管线（方案 3.3.5 的工程化）：**上下文裁剪**（告警函数 + 深度 2 调用闭包 + 引用宏，按字符预算截取）→ **LLM 首判**（强制结构化 JSON）→ **A-RAG**（置信度 < 0.6 触发本地知识库检索后重判）→ **证据行号核对**（引用行必须在函数区间内、为真实代码、且包含告警行本身，否则降级 NEEDS_REVIEW）→ 结论回写 SARIF 与报告。

```bash
uv run ecdet scan examples/svd_demo --no-build -o out
# 离线演示（确定性 Mock LLM，覆盖真判/误报/RAG/降级四条路径）
uv run ecdet triage out/results.sarif --project examples/svd_demo --mock -o out
# 接本地 vLLM / Ollama / LM Studio（OpenAI 兼容端点，数据不出域）
export ECODET_LLM_BASE_URL=http://127.0.0.1:8000/v1
export ECODET_LLM_MODEL=Qwen2.5-Coder-7B-Instruct
uv run ecdet triage out/results.sarif --project examples/svd_demo -o out
```

幻觉抑制三道闸：输出不可解析 JSON → NEEDS_REVIEW；引用行号越界/指向注释/缺告警行 → 降级；LLM 调用失败 → NEEDS_REVIEW。修复建议验证闭环（编译+静态+CBMC）在阶段三后半接入。

## 自建嵌入式漏洞数据集管线（阶段三，P6）

`scripts/build_dataset.py` 实现方案 3.4.3 六步流程（可离线运行，测试内置 git fixture）：

1. **安全通告清单**：CVE/CWE/修复提交/GB/T 30279 严重级/嵌入式上下文标记（ISR/MMIO/RTOS）；
2. **修复提交检索**：`git log` 按 CVE/GHSA/security 关键词辅助发现与校验；
3. **函数切片**：复用 ecdet 词法解析器，修复提交 parent 版本中"文本变化的函数"为漏洞样本，同名修复后版本为配对样本；
4. **预标注**：清单字段 + ISR 命名自动识别（双标注+仲裁在标注平台完成）；
5. **指纹去重**：注释/空白规范化后 SHA-256（PrimeVul 近重复删除方法），全库唯一；
6. **时间划分**：按修复日期 6:2:2 切分 train/val/test，同通告样本不跨集合，杜绝时间泄漏。

```bash
uv run python scripts/build_dataset.py --manifest data/manifest.json --out data/dataset
```

输出 `samples.jsonl`（含 code/指纹/标注/划分）、`stats.json`、`LICENSES.md`（逐仓库许可登记，仅分发切片不整仓再分发）。

## 检测流水线

```
目标工程 ──L1 构建复现──> compile_commands.json
   │                        │
   │                   L3 多引擎分析（自研规则引擎 + cppcheck/clang-tidy/ESBMC 检测到即接入）
   │                        │  ├─ 词法/结构规则（28 条）
   │                        │  ├─ 硬件语义注入（SVD 寄存器权限 + ISR 识别 + RTOS API 语义，P2）
   │                        │  └─ 抽象解释：常量传播 → Proven 分级 / 误报抑制（P4）
   └──源码直扫──────────────┤
                            ▼
              L2 统一告警模型（SARIF 2.1.0 唯一交换格式）
                            ▼
              L4 LLM 分诊（上下文裁剪 → A-RAG → 证据核对，P5）
                            ▼
              L5 聚合去重 + CWE↔MISRA↔GJB 双口径映射
                  + 可证明性分级（Proven/Detected/Suspected）
                            ▼
              results.sarif + report.html（含证据链、分诊结论与合规记录）
```

SVD 文件可通过 `--svd <path>` 指定，缺省自动发现工程内 `*.svd`（未提供时 MMIO 检查跳过，ISR/竞争/阻塞检查仍可用）。

## 内置规则集（阶段二：28 条）

- **MISRA C:2012 子集**（15 条）：2.5 / 7.2 / 8.7 / 8.9 / 13.5 / 14.2 / 15.2 / 15.5 / 16.4 / 16.6 / 17.2 / 17.3 / 21.1 / 21.3 / 21.6
- **CERT C 子集**（5 条）：PRE31-C / MSC30-C / STR31-C / ARR30-C / FIO30-C
- **ECDET 缺陷规则**（4 条）：CWE-242（gets）/ CWE-197（字面量截断）/ CWE-1284（scanf %s 无界）/ CWE-563（未使用参数）
- **ECDET 硬件语义规则**（4 条，阶段二新增，P2）：
  - `ECDET-MMIO-ACCESS`：写只读 / 读只写寄存器（基于 CMSIS-SVD 语义库，`PERIPH->REG` 与直接地址解引用两种形态）
  - `ECDET-ISR-RACE`：ISR 与任务共享全局变量且访问落在临界区区间之外（按行区间判定保护）
  - `ECDET-VOLATILE`：ISR 共享变量未声明 volatile
  - `ECDET-ISR-BLOCK`：ISR 中调用阻塞 API（FreeRTOS/RT-Thread/CMSIS-OS2 语义标注表，提示 FromISR 变体）

外部引擎 cppcheck、clang-tidy、ESBMC 检测到安装即自动接入。

## 可证明性分级（P4 机制，阶段二）

- **Proven**：抽象解释（函数内常量传播）证明数组下标越界 → `CERT C ARR30-C` 以 PROVEN 输出；ESBMC 界内验证失败同理。证明在界内则不告警（误报抑制）。
- **Detected**：确定性词法/规则证据核对确认。
- **Suspected**：疑似告警，需 LLM/人工评审（阶段三接 L4 后收敛）。

## GJB 8114 主题映射

`ecdet/rules_db/gjb_map.json` 为每条内置规则建立 GJB 8114-2013 主题级映射（规则编号需授权文本核实，报告相应标注），合规记录表同时呈现 MISRA/CERT/ECDET 与 GJB 双口径。

## 实施进度（对照方案表 3-5）

- [x] 2026 Q4 阶段一：构建复现工具链 + MISRA 子集规则引擎 MVP + Juliet 接入
- [x] 2027 Q1 阶段二（提前实施）：SVD/ISR/RTOS 硬件语义建模（P2）、抽象解释常量传播（P4 机制）、SARIF 聚合、GJB 主题映射、ESBMC 适配器
- [x] 2027 Q2 阶段三（提前实施）：L4 LLM 分诊层（P5，Mock 全路径可测 + OpenAI 兼容端点接入）、自建数据集采集管线（P6）
- [ ] 阶段三后半：LLM 修复建议生成与编译/静态/CBMC 验证闭环、数据集在线抓取规模化
- [ ] 2027 Q3 阶段四：四基线对比评测与合规报告
- [ ] 2027 Q4 阶段五：试点部署与迭代
