# CodeChecker 静态分析接入审计

审计日期：2026-11-03。对象为 Ericsson CodeChecker 的 C/C++ 静态分析链路。

CodeChecker 负责构建记录、分析器编排、规则配置、报告处理和差分；符号执行、污点分析等由其调度的分析器执行。ecdet 直接依赖并运行这些实现，统一保存结果和证据。能力范围依据[上游功能说明](https://github.com/Ericsson/codechecker)和[分析命令文档](https://github.com/Ericsson/codechecker/blob/master/docs/analyzer/user_guide.md)。

## 对照结果

| 能力 | 本轮审计前 | 当前实现 |
| --- | --- | --- |
| 核心分析器编排 | 已强制调用 analyze/parse | 保持必跑；Clang SA、Clang-Tidy、Cppcheck、GCC、Infer 按真实能力与编译目标调度 |
| 真实构建参数 | 生成的数据库可能遮盖工程原数据库 | 优先原有数据库，保留带引号命令；Linux/macOS 用 CodeChecker log 记录构建 |
| 路径敏感符号执行 | 使用默认单翻译单元分析 | Clang SA 持续运行，路径事件、宏展开、注释信息完整保存 |
| CTU 跨翻译单元 | 没有启用 | 默认先收集全数据库，再分析选定文件；Windows 使用 PCH，其他平台按需解析 |
| Windows CTU | 上游缺少 .exe 检测且 AST 输出路径错误 | 项目兼容入口修复工具检测、盘符路径和 multiprocessing 子进程；中文及长目录通过目录联接传参，缩短 AST 存储路径 |
| 污点分析 | 没有主动启用 | 默认安全/sensitive 规则集包含污点检查器；项目可声明自有输入源、传播、净化、危险接口 |
| 规则目录与指南 | rules() 为空，CLI 启停没有转发 | 动态导入本机检查器目录、描述、标签、CWE；启停转发给上游；报告采用实际执行状态 |
| 项目分析配置 | 仅环境变量入口 | 自动读取 .ecdet/codechecker.json、.clang-tidy、taint.yaml、skip.txt、review_status.yaml |
| 严重级别 | 未完整处理 CRITICAL/STYLE | CRITICAL/HIGH 对应 error，MEDIUM 对应 warning，LOW/STYLE 对应 note，原始值另行保留 |
| 缺陷指纹 | 接收上游哈希但未固定模式 | 默认 context-free-v2，直接保留原生哈希 |
| 偏离与抑制 | 报告中不可审计 | 原生 JSON 保存所有复核状态；被抑制、误报、主动接受的偏离从活动告警中移除 |
| 原始报告/失败诊断 | 临时目录结束即删除 | 每次运行独立保存数据库、配置、目录、PLIST、JSON、SARIF、日志和上游失败复现包 |
| 版本比较 | 只有 ecdet 指纹比较 | 完整扫描额外运行原生 cmd diff，保存 new/resolved/unresolved 三种结果 |
| 部分扫描基线 | 未扫描的告警可能算作已解决 | 基线 v2 保存告警与文件；未复扫的告警保留，旧版缺少文件信息时保守处理 |
| 头文件依赖 | 只有文本包含关系 | CodeChecker TUCollector 使用编译器依赖选择翻译单元，Windows 修复路径和引号解析 |
| Web 与报告 | 只有简化告警 | Web 保存分析器元数据，提供原生报告和日志；SARIF 保留 codeFlows 与完整路径证据 |
| 合规记录 | 外部未启用规则可能被标为合规 | 区分“未执行”“本次未检出”和实际偏离，采用上游执行清单 |
| 修复验收 | 只重放内置文件规则，无法核验原生缺陷 | CLI、Web 和编排修复均在工程副本中运行完整静态链路；拒绝仍存在的原告警、新 error 和分析失败 |
| 评测与消融 | “完整系统”实际只测内置静态规则 | 所有配置均运行 CodeChecker，并记录真实分析器、CTU 状态及原生清单；独立基线仍可分别评测 |
| 源码直扫及样例 | 部分扫描丢失 CTU 提供方，C++ 与平台声明不完整 | 合成全工程数据库后再过滤分析目标；探测可用 C/C++ 标准头；补齐硬件样例的最小平台声明 |

## 默认检测行为

CodeChecker 是项目依赖和默认 L3 引擎，没有启停开关。自研规则与硬件语义检查继续并行补充覆盖，Clang-Tidy 与 Cppcheck 统一交给 CodeChecker，避免重复运行。

默认启用上游 default、sensitive、security、portability 四组规则，并显式启用可用的 GCC analyzer 和 Infer 前缀组，防止上游标签缺失导致分析器空跑。automotive 行业配置还启用可用的 MISRA-C 标签组。检查器数量随版本和安装的分析器变化：本次 Windows 目录探测为 1,399 个，实际启用集合与实际执行的分析器记录在每次运行的 manifest 和上游 metadata 中。指南标签不代表完整实现或认证全部 MISRA/CERT 条款。

ARM Clang 缺少系统头文件参数时，从 arm-none-eabi-gcc 的 Newlib 与 C++ 头文件目录补充参数；不把本机 x86 GCC 用于 ARM 命令。真实芯片的 CPU/FPU、ABI、宏和 SDK 仍以工程的真实编译数据库为准；源码合成数据库只能提供通用 ARM 上下文。

没有编译数据库的源码直扫会保留缺少 C 函数声明的诊断，同时允许 Clang SA 继续符号分析；该兼容参数通过上游 cc-verbatim-args-file 转发，不改变真实编译数据库的诊断策略。包含 SVD 的 ARM 源码直扫使用 ARM 目标。Windows GCC 的输出空设备和绝对路径 SARIF 解析已修复，避免分析成功但告警被错误路径过滤。

## 使用和项目模型

```sh
uv sync
uv run ecdet scan /path/to/project -o /path/to/reports
uv run ecdet rules

# Linux/macOS 上记录真实构建；Windows 不支持上游 log 拦截
uv run ecdet scan /path/to/project --build-command "make clean all"
```

现有 --enable / --disable 同时支持内置规则 ID 和 CodeChecker 原生 checker/group/profile 标识。项目级 .ecdet/codechecker.json 使用上游配置格式，例如：

```json
{
  "analyze": [
    "--analyzer-config", "clangsa:unroll-loops=true"
  ],
  "parse": []
}
```

输入/输出位置和 CTU 阶段由 ecdet 管理，项目文件不能覆盖这些生命周期参数。ECODET_CODECHECKER_CONFIG 可以指定其他配置文件路径。

污点模型文件 .ecdet/taint.yaml 可描述工程自有接口。例如输入数据写入第 0 个参数，随后流入自定义危险接口：

```yaml
Propagations:
  - Name: platform_receive
    DstArgs: [0]
Sinks:
  - Name: platform_execute
    Args: [0]
```

模型采用[Clang 上游 YAML 语义](https://clang.llvm.org/docs/analyzer/user-docs/TaintAnalysisConfiguration.html)，参数从 0 计数，-1 表示返回值。项目应按接口的实际契约建模。

其他自动发现文件：

- .clang-tidy：由原生 Clang-Tidy 读取。
- .ecdet/skip.txt：上游跳过文件规则。
- .ecdet/review_status.yaml：上游复核状态配置。
- 源码中的 codechecker_suppress / codechecker_false_positive 等注释：由上游解析。旧式 suppress 注释在当前版本 JSON 中可表现为 false_positive。

## 产物

每次 CLI 扫描在报告目录的 codechecker/runs/运行ID 下保存原生结果。Web 扫描使用对应运行的报告目录。

```text
codechecker/
  latest.json                   最近一次尝试，含失败状态
  latest-full.json              最近成功的完整扫描
  runs/<运行ID>/
    manifest.json               能力、实际规则、范围、命令、阶段状态
    catalog.json                分析器与检查器目录
    effective-config.json       实际分析参数
    compile_commands.json       实际使用的数据库副本
    reports/                    PLIST、CTU、上游 metadata、失败复现包
    results.json                全部复核状态的原生报告
    results.sarif               原生 SARIF
    reports.baseline            便携原生哈希基线
    diff-{new,resolved,unresolved}.json
    <阶段>.log
```

原生差分只对完整扫描执行，保留所有原生复核状态；活动告警的偏离/抑制变化由 ecdet 基线另行处理。部分扫描不会覆盖最近完整扫描的原生差分基准。

分析失败会返回失败并保存诊断资料；已生成的部分结果仍保留，不会被当成“零告警成功”。Web 失败状态保留产物目录，“分析详情”“原生报告”“分析日志”可直接访问相应资料。

Windows 的源码与报告目录通过短 ASCII 路径交给原生工具；Python 原子写入使用实际目录和扩展长度路径，避免深目录截断以及通过目录映射重命名失败。CTU AST 文件名按源码路径哈希生成，避免再次拼接完整路径。

修复验证另在工程的 ecdet_reports/fix-verification 下保留工程副本与修改前后报告。副本保留生成头文件和编译上下文，将工程内绝对编译路径改为副本路径；项目源码和原数据库不因“建议修复”而改变。验证器复扫完整工程，同时检查目标告警与新增高危告警；分析失败会拒绝补丁。

补丁中未改变的语句通过行映射比较，避免插入终止符等操作把已有错误误判为新增。Web 上传会过滤旧的 ecdet_reports、安装环境和版本库文件；SQLite 读取与提交统一在连接锁内完成，后台任务失败的完整堆栈另存 task-errors。

评测脚本的结果 JSON 含 analysis 字段，记录实际分析器和对应 manifest 路径。新引擎可覆盖原先仅由动态通道发现的缺陷，动态独有贡献按当前静态结果重新计算，不沿用旧版固定比例。

## 环境能力边界

| 能力 | 状态及补齐方式 |
| --- | --- |
| Windows Clang SA / CTU / Clang-Tidy / Cppcheck / GCC | 已安装并实扫验证；ARM 项目跳过不匹配的本机 GCC |
| Infer | Windows 无官方原生支持；Linux x86_64 镜像固化官方 1.3.0 包及 SHA256，已实际检出 infer-nullptr-dereference |
| 统计式缺陷分析 | 已接自动探测与 --stats 执行链路；当前 LLVM 不包含 statisticsCollector/statisticsbased 插件，清单明确标为不可用。未找到与现有 LLVM 匹配且可取得的插件构建，尚未完成该模式的实际验证 |
| Clang 编译器诊断目录 | Windows LLVM 安装包缺少 diagtool；告警目录探测会记录上游提示，Linux 容器安装 clang-tools |

上游统计模式本身要求特定检查器，并非安装 CodeChecker Python 包就会具备。说明见[统计分析章节](https://github.com/Ericsson/codechecker/blob/master/docs/analyzer/user_guide.md#statistical-analysis-mode)。Infer 平台限制见[官方 FAQ](https://fbinfer.com/docs/support/)。

历史统计插件讨论见[上游 issue 805](https://github.com/Ericsson/codechecker/issues/805)，其中引用的 ReturnCheckers 分支目前不可取得；不能把普通 Clang 检查器当作这项能力已补齐。

Docker Desktop 本机的 dockerInference 通信路径故障已恢复：备份设置后禁用 Docker AI，保留故障通信目录的改名备份，再重新启动；没有执行恢复出厂设置。处理参考 [Docker 上游问题 460](https://github.com/docker/desktop-feedback/issues/460) 和 [531](https://github.com/docker/desktop-feedback/issues/531)。完整基础镜像此前已成功构建；本轮最终打包遇到 Docker Hub 网络错误后，使用已构建的本地基础镜像离线安装当前 wheel，避免网络故障阻断交付。

## 验证记录

- 中文路径的双文件 ARM 工程：CTU 检出跨文件 core.DivideZero，保留 CWE-369 和跨文件路径。
- 自定义 platform_receive → platform_execute：检出 optin.taint.GenericTaint。
- 禁用 core.DivideZero 后原生结果消失；源码抑制后活动告警消失，原生 JSON 留存复核状态。
- 插入注释后，同一缺陷的 context-free-v2 哈希保持稳定。
- 原生目录差分识别已解决缺陷；部分扫描仍收集完整 CTU 上下文。
- 最终 Windows 增量实扫仅分析 main.c，数据库仍包含 provider.c；采用短 AST 文件名后继续检出跨文件 core.DivideZero。
- 正常 CLI 流程产出统一 SARIF、HTML 和基线；相关自动测试验证模型往返、规则默认值、基线范围及 Web 产物访问。
- Windows 原生扫描实际运行 Clang SA、Clang-Tidy、Cppcheck、GCC；中文和空格路径的原生告警保留真实路径。
- Windows C++ 实扫包含标准库 vector；四类原生分析器全部执行，core.NullDereference 正常入报。
- Linux 交付镜像实际使用 CodeChecker log 记录 make clean all，运行五类分析器；CTU 除零、Clang/Cppcheck/GCC/Infer 空指针进入统一报告，所有分析器执行状态均来自原生 metadata。
- 最终镜像 ecdet:codechecker-core 的六个关键安装模块 SHA256 与工作区代码相符；五类分析器实扫共输出 6 条聚合告警，命令退出码 1 表示发现缺陷。镜像标识和实扫清单保存为 delivery-verification.json。
- Windows 崩溃测试程序限制自身的错误弹窗，避免把等待弹窗误记为看门狗超时；临时文件清理失败不再丢弃真实动态发现。
- Web 自动写回实际采纳 3 处补丁，error 告警从 9 条降至 6 条，源码备份与原始样例完整性通过断言；C++ 源文件与头文件备份也已核验。
- 一轮 207 项全量回归得到 202 通过、5 失败；发现的验证行号映射、后台并发读取、上传历史报告与 Windows 深目录问题已修正，并分批复测失败用例。最后 24 项重点验收全部通过（pytest-final-acceptance.log，378.84 秒），包含原生 CodeChecker 专项、CLI、Web 写回、配置、产物访问及原生修复回归验证。当前收集到 210 项测试，此处不把分批结果记作一次全量通过。

本次审计的临时工程、原生日志和构建日志位于忽略目录 ecdet_build/codechecker_audit；不随源码提交。
