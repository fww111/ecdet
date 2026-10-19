/*
 * 传感器驱动 —— 集中放置内存类缺陷样例：
 *   STR31-C（strcpy 溢出）、ARR30-C（常量下标越界）、
 *   CWE-197（定宽截断）、MISRA 17.2（递归）、MISRA 15.2（goto）。
 */
#include <string.h>
#include <stdint.h>
#include "demo.h"

#define SENSOR_HISTORY_LEN 8

static uint16_t s_history[SENSOR_HISTORY_LEN];
static uint16_t s_index;

static uint16_t sensor_scale(uint16_t raw)
{
    /* 定宽类型初始化截断：300 不在 uint8_t 范围内 */
    uint8_t gain = 300;
    return (uint16_t)((uint32_t)raw * gain / 100u);
}

/* 直接递归：嵌入式栈深不可控（MISRA 17.2） */
static uint16_t sensor_filter(uint16_t v, uint8_t depth)
{
    if (depth == 0u) {
        return v;
    }
    return sensor_filter(v, (uint8_t)(depth - 1u));
}

uint16_t sensor_sample(void)
{
    uint16_t raw = 0u;
    char label[8];

    /* strcpy 目标 8 字节，源 17 字节：缓冲区溢出（CERT STR31-C） */
    strcpy(label, "SENSOR_01_FULL");

    /* 常量下标越界：s_history[8]（MISRA 17.2 之外的 ARR30-C） */
    s_history[8] = 0u;

    /* goto 破坏单入单出（MISRA 15.2） */
    if (raw == 0u) {
        goto done;
    }
    raw = sensor_scale(raw);
    raw = sensor_filter(raw, 3u);

done:
    s_history[s_index] = raw;
    s_index++;
    if (s_index >= SENSOR_HISTORY_LEN) {
        s_index = 0u;
    }
    return raw;
}

void bsp_init(void)
{
    s_index = 0u;
    (void)memset(s_history, 0, sizeof(s_history));
}
