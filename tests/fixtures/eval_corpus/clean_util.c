/* 评测语料：干净参照（应零告警；utility_helper 触发 8.7 作为可控 FP 源） */
#include <stdint.h>

static uint8_t s_state;

/* 干净函数，但未声明 static 且单翻译单元引用 → MISRA 8.7 note（FP 源） */
int utility_helper(int v)
{
    s_state = (uint8_t)v;
    return s_state;
}

/* 干净函数 */
int add_values(int a, int b)
{
    return utility_helper(a) + b;
}
