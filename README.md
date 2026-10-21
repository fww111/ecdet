# ecdet —— 嵌入式软件代码缺陷与安全漏洞检测系统

面向汽车电子与工业控制场景的嵌入式 C/C++ 代码检测系统。依据《嵌入式软件代码缺陷与安全漏洞检测系统调研与技术方案》**V1.2** 实施，采用"**静态与动态双通道为骨架、LLM 多智能体协同为中枢、工具验证与证据链为约束**"的混合式五层架构（P1–P7 全覆盖）。

## 五层架构（V1.2：L3 静动双通道，L4 六类智能体）

| 层 | 模块 | 解决的问题 |
|----|------|-----------|
| L1 编译环境复现 | `ecdet.l1_build` | P1：任意嵌入式工程 → compile_commands.json |
| L2 统一表示 | `ecdet.l2_ir` | P3：多引擎输出统一为 SARIF 单一数据模型，注入硬件语义（P2） |
| L3 双通道分析 | `ecdet.l3_analysis` | 静态：规则引擎/抽象解释/BMC（P2/P3/P4）；动态：激励建模 + harness 闭环 + 仿真执行（P7，`ecdet.l3_analysis.dynamic`） |
| L4 多智能体协同 | `ecdet.l4_llm` | P5：规划/研判/动态测试/监控/修复/报告六类智能体 + 工具验证闭环 |
| L5 聚合与输出 | `ecdet.l5_report` | P3/P4：去重、CWE↔MISRA↔GJB 映射、Proven/Detected/Suspected 三级、合规报告 |

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

## 检测流水线

```
目标工程 ──L1 构建复现──> compile_commands.json
   │                        │
   │              ┌── L3 静态通道：规则引擎（28 条）+ 硬件语义（P2）+ 抽象解释（P4）
   │              └── L3 动态通道：激励建模 → harness 闭环 → 原生/仿真执行 → PoC oracle（P7）
   └──源码直扫──────────────┤
                            ▼
              L2 统一告警模型（SARIF 2.1.0 唯一交换格式）
                            ▼
         L4 多智能体：分诊扇出（A-RAG + 证据核对）→ 监控裁决 → 修复闭环（P5）
                            ▼
              L5 聚合去重 + CWE↔MISRA↔GJB 双口径
                  + 可证明性分级（Proven/Detected/Suspected）
                            ▼
              results.sarif + report.html（含证据链、PoC 与合规记录）
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

幻觉抑制三道闸：输出不可解析 JSON → NEEDS_REVIEW；引用行号越界/指向注释/缺告警行 → 降级；LLM 调用失败 → NEEDS_REVIEW。

## 增量分析（方案 3.3.6）

大规模工程场景下，深度分析可以嵌入每日集成而非一次性离线行为：

```bash
# 影响集：变更文件 → include 反向闭包 → 调用图反向闭包
uv run ecdet impact <工程> --changed src/sensor.c          # 查看影响集
uv run ecdet scan <工程> --changed src/sensor.c            # 增量扫描（仅影响集内文件）

# 告警基线：差分出 新增/已解决/持续，仅新增告警需要进入 LLM 研判
uv run ecdet scan <工程> --save-baseline -o out            # 首扫存基线
uv run ecdet scan <工程> --baseline out/baseline.json -o out
uv run ecdet triage out/results.sarif --only-new out/baseline.json --mock
```

局限（MVP）：告警指纹含行号，代码移动会使告警计为"新增+已解决"，上下文哈希缓解留待后续。

## L4 修复建议与验证闭环（阶段三后半，P5）

`ecdet fix` 对分诊后的 TRUE_POSITIVE 告警生成函数级补丁，并以 **ToolLoopVerify** 三道验证把关（方案 3.3.5）：

1. **静态重扫**：补丁应用后原告警必须消除，且不得引入新的 error 级告警；
2. **gcc 语法检查**：`-fsyntax-only -std=gnu89`（gcc 可用时自动启用）；
3. 通过验证才产出统一 diff 补丁与修复记录，未通过一律拒绝并记录原因。

```bash
uv run ecdet triage out/results.sarif --project <工程> --mock -o out
uv run ecdet fix out/results.sarif --project <工程> --mock -o out
# 产物：out/fixes/*.patch（统一 diff）+ out/fixes/fixes.json（采纳/拒绝与理由）
```

## 对比评测与消融实验（V1.2 七配置，方案 3.5）

`scripts/run_eval.py` 实现方案 3.5.2 指标体系与 3.5.3 消融设计（V1.2 扩展至七配置）：

- **指标**：函数级 Precision/Recall/F1（主口径）+ 告警级计数、每千行耗时（全量/增量）、可证明性比例、**动态贡献率**（3.5.2 之 6：动态新发现且静态未报占全部已确认缺陷之比）、LLM 误报过滤量；
- **消融**：A0 完整 / A1 去 LLM / A2 去硬件语义 / A3 去 RAG / A5 去动态通道 / A6 单智能体串行（A4 去验证闭环作用于修复验收率）；
- **基线**：cppcheck / clang-tidy / ESBMC 检测到安装即对比（方案 3.5.1）。

```bash
uv run python scripts/run_eval.py --corpus tests/fixtures/eval_corpus     --vuln-funcs "buf_copy_bad,TIM6_IRQHandler,gpio_ro_write,unprotected_reader,scale_value,read_selected"     --svd tests/fixtures/eval_corpus/chip.svd --out eval_out
```

示例语料六配置消融结果（填充 V1.2 表 3-5）：A0 完整系统 P/R=100%（动态贡献率 33%）；A1 去 LLM 精确率降至 50%（8 条误报未过滤，P5 净贡献）；A2 去硬件语义召回降至 50%（P2 净贡献）；A5 去动态通道召回降至 66.7% 且耗时 62s→0.2s（双通道互补性与动态成本同时可见）；A6 与 A0 检测能力等价（组织学消融）。
```

在示例语料上的消融结果（报告填充方案表 3-4 模板）：A1 去 LLM 精确率 44%→100%（LLM 过滤 10 条误报），A2 去硬件语义召回 100%→25%（P2 建模净贡献）。

### Juliet 基准评测（方案 3.4.1 → 3.5 打通）

```bash
# 离线自检（检出率管线 + 语料导出→评测框架 全链路）
uv run python scripts/fetch_juliet.py --selftest

# 联网下载后：导出语料 → 消融评测（juliet 配置屏蔽不适配切片语料的工程级规则）
uv run python scripts/fetch_juliet.py --download --export-corpus --limit 300
uv run python scripts/run_eval.py --corpus data/juliet/corpus \
    --gt data/juliet/gt.jsonl --profile juliet --out eval_juliet --with-baselines
```

## Web 控制台（零依赖）

浏览器完成"注册工程 → 扫描 → 告警浏览/人工复核"全流程。核心设计——**输入的单位是工程目录，三种来源统一归一为服务端可访问目录**：

| 来源 | 操作 | 归一方式 |
|------|------|---------|
| 本地路径 | 填服务端可访问路径 | 零拷贝直引（支持重复/增量扫描） |
| 上传压缩包 | 拖入 zip / tar.gz | 解压到工作区（防路径逃逸） |
| Git 仓库 | URL@分支（私有库带 token） | 浅克隆到工作区 |

```bash
uv run ecdet serve --port 8600     # 打开 http://127.0.0.1:8600
```

界面（v0.9 改版）：侧边栏四页导航——**总览**（工程/运行/告警统计卡、严重级 SVG 环形图、可证明性分布、最近运行）、**工程管理**（三源注册 + 扫描参数弹窗）、**扫描运行**（状态/分级计数/构建通道/耗时/产物链接）、**告警中心**（筛选 + 点击行打开详情抽屉：证据链、LLM 分诊结论与置信度、确认/豁免/重置状态流转）。含空态引导、吐司反馈、加载动效。

扫描参数：行业 profile / SVD / LLM 分诊 Mock 或真实端点 / 动态通道开关；后台任务队列串行执行、进行中任务自动轮询；HTML 报告与 SARIF 可下载；动态载体可用性披露。纯标准库实现（ThreadingHTTPServer + SQLite + 原生 JS/CSS，零外链、离线可用），无新增第三方依赖。

## 一键修复与大模型接入（v1.0）

- **修复建议页**：对已完成运行点「⚙ 一键修复」——对人工确认 / LLM 判真缺陷 / 动态 PoC 三类告警批量生成补丁，经 ToolLoopVerify（静态重扫 + gcc 语法检查）验证后展示 diff（采纳/拒绝与原因），告警详情抽屉同步显示对应补丁；
- **大模型设置页**：前端直接填 Base URL / API Key / 模型名（OpenAI 兼容：vLLM / Ollama / LM Studio），带"测试连接"探针；凭据存本机 SQLite（回传脱敏），保存后分诊与修复即用真实端点，Mock 模式保持离线可用。

## 容器化部署（阶段五试点准备）

```bash
docker build -t ecdet:latest .
docker run --rm -v /path/to/firmware:/work ecdet:latest scan /work
```

镜像内置 cppcheck 基线引擎；LLM 分诊通过 `ECODET_LLM_BASE_URL` 环境变量指向宿主 vLLM 服务。

## 数据集 GHSA 在线抓取（阶段三后半，P6）

```bash
export GITHUB_TOKEN=ghp_xxx
uv run python scripts/build_dataset.py --fetch-ghsa owner/repo \
    --repo path/to/local/clone --license Apache-2.0 --out data/dataset
```

抓取仓库安全通告 → CVSS 分级映射 GB/T 30279 → 以 CVE 号在 git log 定位修复提交 → 进入既有六步管线（切片/去重/时间划分）。

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

## 动态分析通道与运行时监控（V1.2 新增，P7）

V1.2 将动态分析升格为与静态并列的第一类检测通道（方案 3.3.5/3.3.6）。本仓库实现宿主机原生执行载体（三级吞吐-保真梯度的宿主档；Unicorn/Renode 仿真载体为后续扩展）：

- **激励建模**：确定性特殊值表（0/边界/回绕点）+ 乘法散列采样；SVD 寄存器语义经参数名对齐后收窄取值域（"一次建模、静动两用"）；
- **harness 生成-编译-修正闭环**：以解析器产出的参数类型为骨架生成模板 harness（激励组合表嵌入 C 数组，每函数一次编译），链接期未解析符号与 GCC 14+ 隐式声明错误自动打桩重编（完整 stderr 扫描，多错误一次收全）；确定性打桩失败后交 **LLM harness 修正器**（编译日志回传重写，产物须再过编译验证）；
- **执行载体三级吞吐-保真梯度**：宿主原生执行（gcc，可用即用）→ Unicorn CPU 级仿真（`pip install unicorn` 探测即接入，执行回路待固件语料）→ Renode 外设级仿真（renode 二进制探测即接入）；编排日志披露各档可用性；
- **oracle 三类**：崩溃退出码分类（Windows NTSTATUS：除零 0xC0000094 / 空指针 0xC0000005 / 栈溢出等）、UBSan stderr、看门狗超时（疑似死循环）；
- **PoC 可复现**：`harness.exe <seed>` 一键重放，实参组合随告警证据落 SARIF（Detected 级）。

```bash
uv run ecdet orchestrate <工程> --mock    # 六智能体编排：静态→分诊→动态→监控→修复→闸门
```

**运行时监控**（3.3.6）是"静态怀疑、动态裁决"的执行者：静态通道 Suspected 级结论自动转为定向探针，仿真/宿主执行命中即回填 PoC 证据并升级 Detected（LLM 不变量归纳接口预留，候选须静态核验后启用）。

## 多智能体协同（V1.2 新增，P5）

`ecdet orchestrate` 实现方案 3.3.7 六类智能体的确定性编排（LangGraph 状态机 MVP）：规划 → 静态通道 → 分诊并行扇出 → 动态通道 → 运行时监控裁决 → 修复验证闭环 → 高危人工复核闸门 → L5 聚合。采纳边界：LLM 负责编排与语义推理，**不作最终裁决**；成本控制含分层路由（note 级不过 LLM）与结构化交接（AgentState）；`--single-agent` 为 A6 消融/降级形态。

## 内置规则集（30 条）

- **MISRA C:2012 子集**（17 条）：2.5 / 7.2 / 8.7 / 8.9 / **10.3** / **10.4** / 13.5 / 14.2 / 15.2 / 15.5 / 16.4 / 16.6 / 17.2 / 17.3 / 21.1 / 21.3 / 21.6
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

## 实施进度（对照 V1.2 表 3-6）

- [x] 2026 Q4 阶段一：构建复现工具链 + MISRA 子集规则引擎 MVP + Juliet 接入（P1 闭环）
- [x] 2027 Q1 阶段二（提前实施）：SVD/ISR/RTOS 硬件语义建模（P2）、抽象解释常量传播（P4 机制）、SARIF 聚合、GJB 主题映射、ESBMC 适配器
- [x] 2027 Q2 阶段三（提前实施）：LLM 研判/修复机制（3.3.8，P5）+ 自建数据集管线（P6）+ GHSA 抓取
- [x] 2027 Q3 阶段四（提前实施）：消融评测框架（表 3-5 报告产出）、Juliet 基准管线、增量分析（3.3.9）
- [x] **V1.2 新增范围（P7 / 3.3.5-3.3.7）**：动态分析引擎（激励建模 + harness 闭环 + oracle 三类 + PoC 可复现）、运行时监控（Suspected→Detected 裁决）、六智能体编排（`ecdet orchestrate`，结构化交接 + 分层路由 + 人工复核闸门 + 单智能体降级）、消融 A5/A6 与动态贡献率指标
- [x] Web 控制台：工程三源注册（路径/zip/Git）+ 扫描任务队列 + 告警浏览/人工复核状态流转（零依赖）
- [x] Web 一键修复（补丁 diff 展示 + 验证闭环）+ 前端大模型设置（API Key 存本机、测试连接）
- [x] 阶段五准备：Docker 容器化封装（内置 cppcheck 基线）
- [ ] 阶段四后半：Juliet/Toyota ITC 全量基准成稿（联网下载后即可运行）、Unicorn/Renode 仿真载体接入（三级吞吐-保真梯度中档与高档）、LLM harness 生成接入动态测试智能体
- [ ] 2027 Q4 阶段五：试点部署与迭代（真机接入与仿真保真度校准）
