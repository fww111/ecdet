# Tree-sitter与真实接入验收结果

日期：2026年11月3日

本轮完成Tree-sitter上下文接入、真实clang-tidy验收及真实LLM受控验收。最终增强环境全量测试447项通过，0失败、0跳过；相较上一轮新增54项测试。

## 新增功能与修改

| 内容 | 已实现的行为 |
| --- | --- |
| 可选C语法后端 | 提取函数、签名、参数、局部变量、调用、条件和赋值，保留UTF-8字节偏移及行列范围 |
| 精确上下文切片 | 可信AST用于函数定位和调用展开，处理多行签名、中文、CRLF、同行多函数及同行全局声明 |
| 保守调用关联 | 区分直接、间接和宏调用；函数指针遮蔽、条件定义和条件调用保留未解析状态 |
| 显式回退 | 缺少依赖、解析恢复或后端错误时使用基础结构恢复，并保存原因；不把恢复树当作可靠AST |
| 补丁边界保护 | 部分行片段、未求值的条件函数和截断上下文标为待复核，阻止按整行补丁误删相邻代码 |
| 真实工具接入 | clang-tidy支持`ECDET_CLANG_TIDY`路径配置，检测与执行使用同一工具；项目内路径转为相对路径 |
| 报告元数据 | 外部规则补齐RuleMeta，真实告警进入SARIF时具有有效ruleIndex |
| 包启动入口 | 补齐`python -m ecdet`，支持帮助、规则列表、扫描和控制台等现有命令 |
| 可复用验收脚本 | 增加真实clang-tidy正反例与真实LLM的4个受控候选，保存版本、调用、耗时和结果 |

现有静态规则仍使用原规则索引。Tree-sitter首先改善结构索引和LLM上下文，条件与赋值索引供后续规则开发使用。它不提供完整的类型、指针目标或预处理分支可达性证明。

## 真实LLM验收

已使用用户保存的服务配置执行真实请求，模型为`glm-5.3-flash`。配置检查发现界面仍处于Mock模式，已切换为真实端点后运行；没有使用离线客户端代替真实请求。

验收只发送`examples/llm_validation/samples.c`中的受控源码，预期标签由`cases.json`保存并在调用后比对，不进入提示词。4个候选以warning级别测试模型研判，避免将高危FP默认人工复核策略混入模型建议统计。

| 样例 | 内容 | 预期与实际建议 | 引用校验 | 耗时 |
| --- | --- | --- | --- | --- |
| A1 | 数组越界 | TRUE_POSITIVE | 通过 | 5.81秒 |
| A2 | 合法数组下标 | FALSE_POSITIVE | 通过 | 9.30秒 |
| C1 | 字符串拷贝超出缓冲区 | TRUE_POSITIVE | 通过 | 6.94秒 |
| C2 | 合法字符串拷贝 | FALSE_POSITIVE | 通过 | 12.96秒 |

实际调用4次，传输成功4次，结构化结论4例，建议与预期一致4例，需复核0例。验证范围为这4个受控样例，真实项目的准确率、漏报率和修复质量仍需要独立标注集。

候选保持`validation-candidate`引擎和`Suspected`状态。引用有效不等于工具证明缺陷，模型TP没有自动升级为Detected或Proven。结果不记录密钥；token消耗与费用本次没有测量。

## 真实clang-tidy验收

使用本机Visual Studio自带的LLVM20.1.8，没有安装全局工具或修改系统PATH。通过固定检查`clang-analyzer-core.NullDereference`验证两个样例：

- `null_bad.c`：检出1条目标告警，位置为第5行第12列。
- `null_good.c`：检出0条目标告警。

随后实际运行生产适配器并经完整CLI扫描，目标结果仍为1条与0条，报告位置为项目相对路径。SARIF中的所有告警具有规则元数据，真实空指针告警可继续定位到Tree-sitter上下文。

宽检查还在反例上产生了`readability-non-const-parameter`，已保留在报告中，未将其计为空指针误报。

## 测试与故障处理

| 检查 | 结果 |
| --- | --- |
| 增强环境最终全量回归 | 447项通过，0失败、0跳过，用时84.85秒 |
| 基础环境针对性回归 | 138项通过，47项因未安装可选依赖跳过，0失败 |
| examples语法索引 | 10个C文件均为PASS，共38个函数、29个调用 |
| 扩展安装 | `pip install --no-build-isolation -e ".[hardware,syntax]"`成功 |
| 真实clang-tidy及CLI | 固定检查、生产适配器、项目相对路径、规则元数据和上下文关联通过 |
| 真实LLM | 4次调用、4个受控建议符合预期，结构与引用校验通过 |
| 包启动 | `python -m ecdet --help`和`rules`通过 |

本轮先建立失败用例，再修复包入口、语法索引、上下文边界、工具路径配置及元数据问题。测试覆盖UTF-8、CRLF、同行函数、静态函数作用域、函数指针遮蔽、条件编译、恢复树、缺依赖、零预算和源代码范围。

曾有增强与基础全量进程以系统终止状态退出，未生成正常摘要，这两次未计为通过。随后串行重跑增强环境全量得到447项通过，基础模式以针对性回归验证。Windows测试进程设置SetErrorMode(3)，避免崩溃弹窗占用测试程序。

首次自动启动界面时发现缺少包入口，已补齐。后台重启被工具策略拦截后，由用户手动启动并填写服务配置，真实验收随后完成。

## 安装和继续使用

在实际运行界面的Python环境中安装扩展，并重启控制台以加载新代码。已经保存的模型配置仍保存在原数据目录中。

```powershell
python -m pip install -e ".[hardware,syntax]"
python -m ecdet serve --port 8600 --data-dir "../ecdet本地检查/next_round_20261103/webui_data"
```

本机clang-tidy路径可在当前终端设置，不修改系统环境：

```powershell
$env:ECDET_CLANG_TIDY = 'D:\Develop\vs2026\Community\VC\Tools\Llvm\x64\bin\clang-tidy.exe'
python -m ecdet scan path/to/project --no-build
```

真实模型验收可复用已保存设置：

```powershell
python scripts/validate_llm_endpoint.py --settings-db "../ecdet本地检查/next_round_20261103/webui_data/ecdet_web.db" --output-dir ecdet_reports/llm_controlled
```

端点未配置时脚本记录NOT_CONFIGURED，不自动切换Mock；全调用或结构化失败时记录ERROR；COMPLETED表示流程完成，需同时查看建议比对和需复核数量。

## 证据与代码位置

主要代码为`ecdet/l3_analysis/syntax.py`、`checks.py`、`slicer.py`、`triage.py`、`clang_tidy.py`、`engine.py`和`ecdet/__main__.py`。

证据位于相邻目录`ecdet本地检查/next_round_20261103/`：

- `final_full.xml`：447项全量结果。
- `basic_targeted.xml`：基础环境针对性结果。
- `syntax_examples.json`：10个C文件的索引结果。
- `clang_tidy_live/`：工具版本、命令、原始输出、源文件哈希及SARIF。
- `clang_cli_report/`：生产CLI的SARIF、HTML和上下文关联记录。
- `llm_endpoint_real/validation.json`及`results.sarif`：真实模型建议和分项统计。

Tree-sitter使用Python接口与C语法包，版本固定为0.26.0和0.24.2；相关仓库均为MIT许可：[Python接口](https://github.com/tree-sitter/py-tree-sitter)、[C语法](https://github.com/tree-sitter/tree-sitter-c)。

