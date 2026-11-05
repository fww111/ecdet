# 显式业务契约检测样例

本目录复现6项业务逻辑漏报。检测器按JSON指定的函数编译原始C源码，插入目标入口观测，再执行人工定义的业务断言。契约是输入需求；检测器不从函数名或注释猜测500毫秒、750毫秒和800等阈值。

`projects/`保留完整目标源文件、头文件及所需真实依赖。前4个工程来自2026年11月4日生成的模拟航天样例，EPS来自`fww111/ecdet`的`61c9820a18416ccafd1a0073d60bd62a3fc848f2`提交。目标源码保持缺陷版内容；参考版只在输出目录按`reference_changes.json`生成。

|契约|需求|测试输入|
|---|---|---|
|E02|星敏感器有效且数据年龄≤500毫秒才融合|有效/无效、499/500/501毫秒、计时回绕|
|D02|安全模式禁止科学仪器上电|全部4个模式|
|L04|左右触地信号同时有效才关闭发动机|全部4种布尔组合|
|O03|目标有效且导航数据年龄≤750毫秒|有效/无效、749/750/751毫秒、计时回绕|
|O04|许可、抓捕模式、距离及绝对速度互锁|7种模式、7种正负速度、3种距离、许可开关|
|R-EPS-01|有效通道占空比≤800，合法值原样设置|799/800/801、900、UINT32_MAX及无效通道|

安装Ecdet及`syntax`依赖，准备可运行的宿主GCC。完整扫描还需要CodeChecker工具链。在仓库根目录运行：

```powershell
python examples/business_contracts/prepare.py --compiler gcc
python -m ecdet scan examples/business_contracts/projects/01_earth_observer --no-build --contracts examples/business_contracts/contracts/01_earth_observer/contracts.json --contract-compiler gcc -o ecdet_reports/business-earth
```

`--contracts`显式启用受信任C测试驱动的编译与执行。输出包含统一SARIF、HTML以及`business-contracts/contracts.json`。发现业务断言失败时，规则`ECDET-BUSINESS-CONTRACT`输出Detected级告警；编译失败、缺工具、超时或目标没有执行时，保留ERROR、UNSUPPORTED或TIMEOUT，CLI返回2。

独立重放6对缺陷版/参考版，不运行其他静态引擎：

```powershell
python examples/business_contracts/verify_pairs.py --output ecdet_reports/business-pairs --compiler gcc
```

预期结果是6个缺陷版FAIL、6个参考版PASS，参考版共1297条断言。FAIL需要同时观察到真实目标入口、失败断言和约定退出码。PASS需要目标入口、至少一条执行过的断言及正常退出；空main或陈旧可执行文件不能通过验证。

JSON版本为1；每条契约包含唯一`id`、工程内`source`、目标`function`、相对契约目录的`harness`及`requirement`，可通过`sources`列出工程内链接依赖。源文件和测试驱动均必须位于各自允许的根目录内。

这些结果覆盖给定输入与宿主执行环境。普通静态扫描仍单独统计；只有显式启用本批契约时，才把对应动态检出加入样例覆盖率。板级中断时序、MMIO和真实调度需要另行验证。
