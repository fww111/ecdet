# ecdet —— 嵌入式软件代码缺陷与安全漏洞检测系统

面向汽车电子与工业控制场景的嵌入式C/C++代码检测系统。静态规则与动态测试产生初始告警，LLM提供研判、函数补丁和测试驱动修正建议，工具检查分别记录证据与验证状态。已实现的保护和测试范围见[LLM整改结果](调研/LLM约束整改与验证结果_20261103.md)。

## 五层架构

| 层 | 模块 | 解决的问题 |
|----|------|-----------|
| L1 编译环境复现 | `ecdet.l1_build` | P1：任意嵌入式工程 → compile_commands.json |
| L2 统一表示 | `ecdet.l2_ir` | P3：多引擎输出统一为 SARIF 单一数据模型，注入硬件语义（P2） |
| L3 双通道分析 | `ecdet.l3_analysis` | 静态：规则引擎/抽象解释/BMC（P2/P3/P4）；动态：激励建模 + harness 闭环 + 仿真执行（P7，`ecdet.l3_analysis.dynamic`） |
| L4任务编排 | `ecdet.l4_llm` | 规划、研判、动态测试、监控、修复和报告六类任务；LLM参与研判与修复建议 |
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

## 寄存器描述增强与写1清零检查

安装硬件解析扩展后，扫描会自动使用cmsis-svd 0.6展开寄存器数组、分组偏移和外设继承，并读取位字段的权限和写入语义。源码与许可证见[cmsis-svd仓库](https://github.com/cmsis-svd/cmsis-svd)，解析器采用Apache-2.0许可，厂商SVD数据按各自许可使用。

```bash
python -m pip install -e ".[hardware]"
python -m ecdet scan examples/svd_enhanced_demo --no-build -o ecdet_reports/svd_enhanced
```

`ECDET-MMIO-W1C`检查明确具有写1清零语义的寄存器读改写，包括复合赋值、自增减和同一语句中的寄存器读回赋值。报告包含源码位置、寄存器地址和写1清零位掩码，混合字段的写入方式需依据字段语义核对。例如，`STATUS |= FLAG_A`可能把读取到的其他置位状态一并写回并清除；直接写入待清除位的掩码不触发这条读改写规则。

基础安装继续支持简单SVD及字段解析，并提示当前解析能力。数组、分组和继承需要硬件扩展；缺少扩展或SVD无效时会明确记录MMIO检查跳过。损坏文件、未知访问权限和非法数值不会静默转换为默认可读写寄存器。

clang-tidy适配器同时解析标准输出与标准错误，支持Windows路径并去重。运行日志区分工具缺失、编译数据库无效、超时、编译失败和正常完成；超时保留已产生的诊断。

## 可选C语法结构分析

```powershell
python -m pip install -e ".[hardware,syntax]"
```

`syntax`扩展使用Tree-sitter提取C函数、直接和间接调用、条件与赋值的精确源码范围。LLM上下文优先使用可靠AST，并记录结构来源、实际片段与未解析调用。宏、指针和条件编译不被当作已解决的语义；依赖缺失、语法恢复或后端错误时明确回退基础结构分析。现有规则索引继续保留。

真实接入可用以下脚本复查：

```powershell
python scripts/validate_clang_tidy.py --binary path/to/clang-tidy --output-dir ecdet_reports/clang_tidy_live
python scripts/validate_llm_endpoint.py --settings-db path/to/ecdet_web.db --output-dir ecdet_reports/llm_controlled
```

生产扫描可通过`ECDET_CLANG_TIDY`指定工具路径，使用与可用性检测一致的二进制。LLM验收只发送4个受控候选，密钥从环境变量或只读设置库读取；没有配置时记录未执行。真实运行记录、测试范围与安装说明见[Tree-sitter与真实接入验收结果](调研/Tree-sitter与真实接入验收结果_20261103.md)。

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

分诊管线：上下文裁剪→LLM建议→低置信检索重判→引用与采纳条件核对→回写SARIF与报告。默认低于0.6触发一次规则知识检索重判，最终仍低置信时需复核。TP与FP使用相同的引用门槛；error级误报建议默认需人工复核。实际提供的片段、未解析调用和截断状态均会记录，引用有效不等于缺陷语义已经证明。

```bash
uv run ecdet scan examples/svd_demo --no-build -o out
# 离线演示（确定性 Mock LLM，覆盖真判/误报/RAG/降级四条路径）
uv run ecdet triage out/results.sarif --project examples/svd_demo --mock -o out
# 使用本地端点时，核对实际配置地址与部署范围
export ECODET_LLM_BASE_URL=http://127.0.0.1:8000/v1
export ECODET_LLM_MODEL=Qwen2.5-Coder-7B-Instruct
uv run ecdet triage out/results.sarif --project examples/svd_demo -o out
```

响应结构、有限置信度和整数引用不合格时转需复核。最终调用失败限制在当前告警；有界重试可恢复，尝试历史保留。缺少上下文时覆盖旧研判，避免沿用过时结论。

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

## 代码浏览与版本对比（v1.2，SonarQube Code / GitHub diff 式）

以"文件为中心"重构前端信息架构：侧边栏按 **分析 / 工程与代码 / 结果与处置** 三组重组为七页，新增两页——

- **代码浏览**（SonarQube Code 页式）：每次扫描完成自动定格**源码快照**（`ecdet/webui/snapshot.py`，C/H 文件按 run 存 `snapshots/<run_id>/` + manifest 哈希清单，path 直引工程同样快照，修复改写不再破坏历史视图）；左侧文件树按告警数着色，右侧整文件代码视图（自研 C 语法高亮）+ 告警行整行高亮 + gutter 标记（点击即开告警抽屉）+ 文件内告警 ↑↓ 导航；
- **版本对比**（GitHub Files changed + CodeChecker 告警差分）：任选两次运行——文件级变更（manifest 哈希比对，新增/修改/删除）+ 告警差分三态（New / Resolved / Unresolved，基于告警指纹）；单文件 diff 支持统一/并排切换、双侧行号、行内词级高亮、diff 行边的新增告警标记；
- **告警中心**：severity facet 计数 chips 一键筛选；详情抽屉新增"代码上下文（本运行快照）"块（告警行 ±5 行渲染，可跳转代码浏览）；
- 新增 API：`/api/runs/{id}/files`、`/file`、`/diff`、`/diff/file`（manifest 白名单防路径穿越）；修复补丁记录回填 `alert_id`（告警抽屉补丁匹配此前恒失效的缺陷一并修复）。

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

V1.2将动态分析升格为与静态并列的检测通道。源码函数使用宿主机harness；新增libFuzzer覆盖率测试和Renode固件执行入口，见下方使用说明。

- **激励建模**：确定性特殊值表（0/边界/回绕点）+ 乘法散列采样；SVD 寄存器语义经参数名对齐后收窄取值域（"一次建模、静动两用"）；
- **harness 生成-编译-修正闭环**：以解析器产出的参数类型为骨架生成模板 harness（激励组合表嵌入 C 数组，每函数一次编译），链接期未解析符号与 GCC 14+ 隐式声明错误自动打桩重编（完整 stderr 扫描，多错误一次收全）；确定性打桩失败后交 **LLM harness 修正器**（编译日志回传重写，产物须再过编译验证）；
- **执行载体**：现有源码harness使用gcc宿主执行；覆盖率引导测试使用`fuzz`命令；Renode的ELF加载、UART输入与输出判据使用`firmware`命令。Unicorn目前仅提供可用性探测；
- **oracle 三类**：崩溃退出码分类（Windows NTSTATUS：除零 0xC0000094 / 空指针 0xC0000005 / 栈溢出等）、UBSan stderr、看门狗超时（疑似死循环）；
- **PoC 可复现**：`harness.exe <seed>` 一键重放，实参组合随告警证据落 SARIF（Detected 级）。

```bash
uv run ecdet orchestrate <工程> --mock    # 六智能体编排：静态→分诊→动态→监控→修复→闸门
```

**运行时监控**（3.3.6）是"静态怀疑、动态裁决"的执行者：静态通道 Suspected 级结论自动转为定向探针，仿真/宿主执行命中即回填 PoC 证据并升级 Detected（LLM 不变量归纳接口预留，候选须静态核验后启用）。

## 多智能体协同（V1.2 新增，P5）

`ecdet orchestrate`按确定性流程组织六类任务：规划→静态扫描→分诊→动态测试→监控关联→修复验证→复核状态→报告。规划、调度和汇聚由代码完成，LLM参与研判与修复建议。高危误报建议默认待复核；显式`--auto-accept`也只接受证据合格的建议。分诊、重判、补丁和harness共享`--max-llm-calls`指定的调用次数上限，默认64次，记录模式与调用状态；该上限不代表token或费用预算。

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
- [x] Web 代码浏览 + 版本对比（v1.2）：运行级源码快照、整文件代码视图（C 高亮 + 告警行标注）、两 run 文件 diff 与告警 New/Resolved 差分、告警抽屉代码上下文
- [x] 阶段五准备：Docker 容器化封装（内置 cppcheck 基线）
- [x] 开源组件改造第3—5步：libFuzzer覆盖率测试、Z3局部路径约束、Renode最小STM32F4固件UART执行闭环，提供CLI、SARIF和HTML报告
- [ ] 阶段四后半：Juliet/Toyota ITC全量基准、Unicorn执行、更多Renode平台与外设、中断场景及LLM动态测试扩展
- [ ] 2027 Q4 阶段五：试点部署与迭代（真机接入与仿真保真度校准）

## 覆盖率测试、路径约束与固件仿真

三个后端均可独立运行，结果进入现有SARIF和HTML报告，并保存分项状态与原始证据。

```powershell
python -m pip install -e ".[hardware,syntax,constraints]"
python -m ecdet constraints examples/constraints_demo/bounds.c
python -m ecdet scan examples/constraints_demo --no-build --constraints

python -m ecdet fuzz examples/libfuzzer_demo --harness harness.c --source packet_bad.c --clang path/to/clang.exe --runs 5000 --timeout 20

python scripts/validate_renode.py --clang path/to/clang.exe --renode path/to/renode.exe --output-dir ecdet_reports/renode
python -m ecdet firmware ecdet_reports/renode/good/firmware.elf --platform examples/renode_demo/stm32f4_minimal.repl --renode path/to/renode.exe --input-hex 73 --expect ECDET_BOOT_OK --expect ECDET_STATUS_OK --failure-marker ECDET_SELFTEST_FAIL
```

`fuzz`使用LLVMFuzzerTestOneInput入口、SanitizerCoverage、AddressSanitizer和UndefinedBehaviorSanitizer；字节缓冲区接口可通过`generate_byte_harness`生成驱动模板。保存输入语料、覆盖记录、可执行文件与输入哈希，并独立重放错误输入；重放确认后才生成Detected事件。LLVM的Windows GNU发行版使用显式compiler-rt链接方式，具体编译参数记录在结果中。环境变量`ECDET_CLANG`可指定工具路径。

`constraints`从源码提取受限C子集的整数类型、分支与数组下标，记录SMT和候选输入。SAT候选保持Suspected；UNSAT只对应记录的局部访问。8位字节、16位short与32位int构成当前模型；不支持的代码、缺少依赖与求解超时有明确状态。`--timeout-ms`限制每次求解的时间。显式请求的检查未完成时，命令使用退出码2；发现候选使用退出码1。

`firmware`使用明确指定的ELF、REPL平台、UART接口、输入和输出判据。在独立UART文件中检查结果，保存重放脚本、版本与哈希；脚本完成哨兵、加载错误和墙钟超时共同控制状态。只有实际输出失败标记才产生固件级事件，缺少预期文本会使验收失败。环境变量`ECDET_RENODE`可指定工具路径。当前示例验证最小STM32F4模型的启动与串口响应；真实硬件与其他外设需要各自验收。

三个后端还可通过网页左侧“专项分析”使用：选择已注册工程与分析类型，填写参数后启动任务，在同页查看状态、历史记录并下载报告和原始证据。展开“工具配置与可用性”可保存Clang、Renode路径；该设置与LLM配置分别保存。原有扫描的动态开关继续执行源码harness。

网页路径以所选工程根目录为基准，固件、REPL、驱动、额外源码与语料均需位于工程内。路径约束可指定单个C文件和函数，留空则检查工程中受支持的代码；覆盖率测试需提供测试驱动及目标源码；固件仿真需提供ELF、平台描述和至少一个输出判据。Z3候选、动态重放问题、部分完成、工具缺失及执行失败分别显示。

使用方法与实证见[第3—5步改造与验收结果](调研/第3至5步改造与验收结果_20261103.md)和[网页接入与验收结果](调研/三项分析功能网页接入与验收结果_20261103.md)。
