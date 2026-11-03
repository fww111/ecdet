/* 评测语料：动态通道专项（P7 双通道互补验证）。
 * CodeChecker 可静态检出条件空指针；未约束参数除零由动态补充，
 * 动态通道以真触发 PoC 复核缺陷（Detected 级）。 */
#include <stdint.h>

/* 漏洞函数：除零（divisor 可为 0，静态无除零规则） */
int scale_value(int base, int divisor)
{
    return base / divisor;
}

/* 漏洞函数：条件空指针解引用（sel > 100 时 p 为 NULL） */
int read_selected(char *buf, int sel)
{
    const char *p = (sel > 100) ? 0 : buf;
    return p[0];
}

/* 干净函数：除数有守卫 */
int scale_safe(int base, int divisor)
{
    if (divisor == 0) {
        return -1;
    }
    return base / divisor;
}
