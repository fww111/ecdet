# 月面着陆器嵌入式软件样例

下降阶段切换、雷达测高与高度预测融合、推力调节、推进剂预算、双触地传感器确认与着陆后遥测。

该工程为含预置缺陷的主机模拟样例。七个周期任务通过共享状态、命令队列和事件日志协作；硬件访问落到内存中的寄存器、Flash与收发缓存。调度器采用确定性协作调度，适合重放数据路径与时序边界。真实RTOS抢占、DMA、中断竞争和实物控制时序需另建执行环境。

## 构建与运行

```powershell
python build.py --run
```

此命令用GCC编译所有源文件，生成compile_commands.json，运行200个100ms模拟步并检查正常路径。编译记录位于build/build.log，运行记录位于build/nominal.log。也可使用CMake构建。

```powershell
.\build\spacecraft.exe --ticks 600 --seed 42
.\build\spacecraft.exe --frame command.bin --ticks 200
```

输入帧采用样例自定义格式：2字节opcode、2字节sequence、2字节payload长度、payload、2字节CRC16，所有多字节字段为大端。CRC初值为0xffff，多项式为0x1021，覆盖CRC之前的字节。启动时已发出sequence=1的自检ping，外部帧应使用sequence=2。该格式用于本地重放。

## 模块入口

src/app.c负责命令分发与七个任务注册；src/mission.c实现任务状态机；include/mission.h定义该场景的数据与接口。platform.c实现寄存器、Flash、CRC和确定性时钟，packet.c、storage.c、scheduler.c分别处理通信、日志和调度。其余场景模块实现传感器融合、载荷或执行器业务。

共16个C/头文件、1136个物理行，其中1070个非空行。每个工程包含8处预置缺陷，位置、触发输入与参考修改保存在样例集外层evaluation目录；扫描时以本工程根目录为目标。
