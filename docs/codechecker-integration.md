# CodeChecker静态分析接入审计

审计日期：2026-11-03。对象为Ericsson CodeChecker的C/C++静态分析链路。

本文保留仓库提交`74e588c`中的集成审计，工具清单与验收数字对应原记录的环境。本轮合并验收以[修改总结](本次代码修改总结_20261103.md)和[本机分析器回执](validation_20261103/native_analyzers.json)为准：Clang SA、Clang-Tidy和GCC可用，Cppcheck、Infer、CTU及统计分析插件在本机此次验收环境中不可用。

CodeChecker负责构建记录、分析器编排、规则配置、报告处理和差分；符号执行、污点分析等由其调度的分析器执行。ecdet直接依赖并运行这些实现，统一保存结果和证据。能力范围依据[上游功能说明](https://github.com/Ericsson/codechecker)和[分析命令文档](https://github.com/Ericsson/codechecker/blob/master/docs/analyzer/user_guide.md)。

## 集成对照（原提交审计）

| 能力 | 原提交审计前 | 原提交实现 |
| --- | --- | --- |
| 核心分析器编排 | 已强制调用analyze/parse | 保持必跑；Clang SA、Clang-Tidy、Cppcheck、GCC、Infer按真实能力与编译目标调度 |
| 真实构建参数 | 生成的数据库可能遮盖工程原数据库 | 优先原有数据库，保留带引号命令；Linux/macOS用CodeChecker log记录构建 |
| 路径敏感符号执行 | 使用默认单翻译单元分析 | Clang SA持续运行，路径事件、宏展开、注释信息完整保存 |
| CTU跨翻译单元 | 没有启用 | 默认先收集全数据库，再分析选定文件；Windows使用PCH，其他平台按需解析 |
| Windows CTU | 上游缺少`.exe`检测且AST输出路径错误 | 项目兼容入口修复工具检测、盘符路径和multiprocessing子进程；中文及长目录通过目录联接传参，缩短AST存储路径 |
| 污点分析 | 没有主动启用 | 默认安全/sensitive规则集包含污点检查器；项目可声明自有输入源、传播、净化、危险接口 |
| 规则目录与指南 | `rules()`为空，CLI启停没有转发 | 动态导入本机检查器目录、描述、标签、CWE；启停转发给上游；报告采用实际执行状态 |
| 项目分析配置 | 仅环境变量入口 | 自动读取`.ecdet/codechecker.json`、`.clang-tidy`、`taint.yaml`、`skip.txt`、`review_status.yaml` |
| 严重级别 | 未完整处理CRITICAL/STYLE | CRITICAL/HIGH对应error，MEDIUM对应warning，LOW/STYLE对应note，原始值另行保留 |
| 缺陷指纹 | 接收上游哈希但未固定模式 | 默认context-free-v2，直接保留原生哈希 |
| 偏离与抑制 | 报告中不可审计 | 原生JSON保存所有复核状态；被抑制、误报、主动接受的偏离从活动告警中移除 |
| 原始报告/失败诊断 | 临时目录结束即删除 | 每次运行独立保存数据库、配置、目录、PLIST、JSON、SARIF、日志和上游失败复现包 |
| 版本比较 | 只有ecdet指纹比较 | 完整扫描额外运行原生cmd diff，保存new/resolved/unresolved三种结果 |
| 部分扫描基线 | 未扫描的告警可能算作已解决 | 基线v2保存告警与文件；未复扫的告警保留，旧版缺少文件信息时保守处理 |
| 头文件依赖 | 只有文本包含关系 | CodeChecker TUCollector使用编译器依赖选择翻译单元，Windows修复路径和引号解析 |
| Web与报告 | 只有简化告警 | Web保存分析器元数据，提供原生报告和日志；SARIF保留codeFlows与完整路径证据 |
| 合规记录 | 外部未启用规则可能被标为合规 | 区分“未执行”“本次未检出”和实际偏离，采用上游执行清单 |
| 修复验收 | 只重放内置文件规则，无法核验原生缺陷 | CLI、Web和编排修复均在工程副本中运行完整静态链路；拒绝仍存在的原告警、新error和分析失败 |
| 评测与消融 | “完整系统”实际只测内置静态规则 | 所有配置均运行CodeChecker，并记录真实分析器、CTU状态及原生清单；独立基线仍可分别评测 |
| 源码直扫及样例 | 部分扫描丢失CTU提供方，C++与平台声明不完整 | 合成全工程数据库后再过滤分析目标；探测可用C/C++标准头；补齐硬件样例的最小平台声明 |

## 默认检测行为

CodeChecker是项目依赖和默认L3引擎，没有启停开关。自研规则与硬件语义检查继续补充覆盖，Clang-Tidy与Cppcheck统一交给CodeChecker，避免重复运行。

默认启用上游default、sensitive、security、portability四组规则，并显式启用可用的GCC analyzer和Infer前缀组，防止上游标签缺失导致分析器空跑。automotive行业配置还启用可用的MISRA-C标签组。检查器数量随版本和安装的分析器变化：原审计Windows目录探测为1,399个，实际启用集合与实际执行的分析器记录在每次运行的manifest和上游metadata中。指南标签不代表完整实现或认证全部MISRA/CERT条款。

ARM Clang缺少系统头文件参数时，从arm-none-eabi-gcc的Newlib与C++头文件目录补充参数；不把本机x86 GCC用于ARM命令。真实芯片的CPU/FPU、ABI、宏和SDK仍以工程的真实编译数据库为准；源码合成数据库只能提供通用ARM上下文。

没有编译数据库的源码直扫会保留缺少C函数声明的诊断，同时允许Clang SA继续符号分析；该兼容参数通过上游cc-verbatim-args-file转发，不改变真实编译数据库的诊断策略。包含SVD的ARM源码直扫使用ARM目标。Windows GCC的输出空设备和绝对路径SARIF解析已修复，避免分析成功但告警被错误路径过滤。

## 使用和项目模型

```sh
uv sync
uv run ecdet scan /path/to/project -o /path/to/reports
uv run ecdet rules

# Linux/macOS 上记录真实构建；Windows 不支持上游 log 拦截
uv run ecdet scan /path/to/project --build-command "make clean all"
```

现有`--enable`/`--disable`同时支持内置规则ID和CodeChecker原生checker/group/profile标识。项目级`.ecdet/codechecker.json`使用上游配置格式，例如：

```json
{
  "analyze": [
    "--analyzer-config", "clangsa:unroll-loops=true"
  ],
  "parse": []
}
```

输入/输出位置和CTU阶段由ecdet管理，项目文件不能覆盖这些生命周期参数。ECODET_CODECHECKER_CONFIG可以指定其他配置文件路径。

污点模型文件`.ecdet/taint.yaml`可描述工程自有接口。例如输入数据写入第0个参数，随后流入自定义危险接口：

```yaml
Propagations:
  - Name: platform_receive
    DstArgs: [0]
Sinks:
  - Name: platform_execute
    Args: [0]
```

模型采用[Clang上游YAML语义](https://clang.llvm.org/docs/analyzer/user-docs/TaintAnalysisConfiguration.html)，参数从0计数，-1表示返回值。项目应按接口的实际契约建模。

其他自动发现文件：

- .clang-tidy：由原生Clang-Tidy读取。
- .ecdet/skip.txt：上游跳过文件规则。
- .ecdet/review_status.yaml：上游复核状态配置。
- 源码中的codechecker_suppress / codechecker_false_positive等注释：由上游解析。旧式suppress注释在当前版本JSON中可表现为false_positive。

## 产物

每次CLI扫描在报告目录的codechecker/runs/运行ID下保存原生结果。Web扫描使用对应运行的报告目录。

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

原生差分只对完整扫描执行，保留所有原生复核状态；活动告警的偏离/抑制变化由ecdet基线另行处理。部分扫描不会覆盖最近完整扫描的原生差分基准。

分析失败会返回失败并保存诊断资料；已生成的部分结果仍保留，不会被当成“零告警成功”。Web失败状态保留产物目录，“分析详情”“原生报告”“分析日志”可直接访问相应资料。

Windows的源码与报告目录通过短ASCII路径交给原生工具；Python原子写入使用实际目录和扩展长度路径，避免深目录截断以及通过目录映射重命名失败。CTU AST文件名按源码路径哈希生成，避免再次拼接完整路径。

修复验证另在工程的ecdet_reports/fix-verification下保留工程副本与修改前后报告。副本保留生成头文件和编译上下文，将工程内绝对编译路径改为副本路径；项目源码和原数据库不因“建议修复”而改变。验证器复扫完整工程，同时检查目标告警与新增高危告警；分析失败会拒绝补丁。

补丁中未改变的语句通过行映射比较，避免插入终止符等操作把已有错误误判为新增。Web上传会过滤旧的ecdet_reports、安装环境和版本库文件；SQLite读取与提交统一在连接锁内完成，后台任务失败的完整堆栈另存task-errors。

评测脚本的结果JSON含analysis字段，记录实际分析器和对应manifest路径。新引擎可覆盖原先仅由动态通道发现的缺陷，动态独有贡献按当前静态结果重新计算，不沿用旧版固定比例。

## 原提交环境能力边界

| 能力 | 状态及补齐方式 |
| --- | --- |
| Windows Clang SA / CTU / Clang-Tidy / Cppcheck / GCC | 已安装并实扫验证；ARM项目跳过不匹配的本机GCC |
| Infer | Windows无官方原生支持；Linux x86_64镜像固化官方1.3.0包及SHA256，已实际检出infer-nullptr-dereference |
| 统计式缺陷分析 | 已接自动探测与`--stats`执行链路；当前LLVM不包含statisticsCollector/statisticsbased插件，清单明确标为不可用。未找到与现有LLVM匹配且可取得的插件构建，尚未完成该模式的实际验证 |
| Clang编译器诊断目录 | Windows LLVM安装包缺少diagtool；告警目录探测会记录上游提示，Linux容器安装clang-tools |

上游统计模式本身要求特定检查器，并非安装CodeChecker Python包就会具备。说明见[统计分析章节](https://github.com/Ericsson/codechecker/blob/master/docs/analyzer/user_guide.md#statistical-analysis-mode)。Infer平台限制见[官方FAQ](https://fbinfer.com/docs/support/)。

历史统计插件讨论见[上游issue 805](https://github.com/Ericsson/codechecker/issues/805)，其中引用的ReturnCheckers分支目前不可取得；不能把普通Clang检查器当作这项能力已补齐。

Docker Desktop本机的dockerInference通信路径故障已恢复：备份设置后禁用Docker AI，保留故障通信目录的改名备份，再重新启动。处理参考[Docker上游问题460](https://github.com/docker/desktop-feedback/issues/460)和[531](https://github.com/docker/desktop-feedback/issues/531)。完整基础镜像此前已成功构建；原审计最终打包遇到Docker Hub网络错误后，使用已构建的本地基础镜像离线安装当时的wheel。

## 原提交验证记录

- 中文路径的双文件ARM工程：CTU检出跨文件core.DivideZero，保留CWE-369和跨文件路径。
- 自定义platform_receive → platform_execute：检出optin.taint.GenericTaint。
- 禁用core.DivideZero后原生结果消失；源码抑制后活动告警消失，原生JSON留存复核状态。
- 插入注释后，同一缺陷的context-free-v2哈希保持稳定。
- 原生目录差分识别已解决缺陷；部分扫描仍收集完整CTU上下文。
- 最终Windows增量实扫仅分析main.c，数据库仍包含provider.c；采用短AST文件名后继续检出跨文件core.DivideZero。
- 正常CLI流程产出统一SARIF、HTML和基线；相关自动测试验证模型往返、规则默认值、基线范围及Web产物访问。
- Windows原生扫描实际运行Clang SA、Clang-Tidy、Cppcheck、GCC；中文和空格路径的原生告警保留真实路径。
- Windows C++实扫包含标准库vector；四类原生分析器全部执行，core.NullDereference正常入报。
- Linux交付镜像实际使用CodeChecker log记录make clean all，运行五类分析器；CTU除零、Clang/Cppcheck/GCC/Infer空指针进入统一报告，所有分析器执行状态均来自原生metadata。
- 最终镜像ecdet:codechecker-core的六个关键安装模块SHA256与工作区代码相符；五类分析器实扫共输出6条聚合告警，命令退出码1表示发现缺陷。镜像标识和实扫清单保存为delivery-verification.json。
- Windows崩溃测试程序限制自身的错误弹窗，避免把等待弹窗误记为看门狗超时；临时文件清理失败不再丢弃真实动态发现。
- Web自动写回实际采纳3处补丁，error告警从9条降至6条，源码备份与原始样例完整性通过断言；C++源文件与头文件备份也已核验。
- 一轮207项全量回归得到202通过、5失败；发现的验证行号映射、后台并发读取、上传历史报告与Windows深目录问题已修正，并分批复测失败用例。最后24项重点验收全部通过（pytest-final-acceptance.log，378.84秒），包含原生CodeChecker专项、CLI、Web写回、配置、产物访问及原生修复回归验证。原审计共收集210项测试。

本次审计的临时工程、原生日志和构建日志位于忽略目录ecdet_build/codechecker_audit；不随源码提交。
