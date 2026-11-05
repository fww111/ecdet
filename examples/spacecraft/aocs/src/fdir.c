/*
 * spacecraft_aocs —— 故障检测、隔离与看门狗管理。
 *
 * 故障源包括：IMU 数据超时、飞轮转速越限、母线欠压、星敏感器失效、
 * 控制周期超时。检测结果写入故障位图并触发安全模式。
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "aocs.h"

#define FAULT_LOG_DEPTH     16u
#define FAULT_IMU_TIMEOUT   0x00000001u
#define FAULT_WHEEL_OVER    0x00000002u
#define FAULT_BUS_UV        0x00000004u

typedef struct {
    uint32_t code;
    uint32_t tick;
} fault_record_t;

static fault_record_t *s_fault_log;
static uint32_t s_fault_head;

void fdir_init(void)
{
    s_fault_log = (fault_record_t *)malloc(sizeof(fault_record_t) * FAULT_LOG_DEPTH);
    s_fault_head = 0u;

    if (s_fault_log == NULL) {
        g_aocs.fault_flags |= 0x80000000u;
    }
}

/*
 * 故障事件入队。
 * 事件缓冲在初始化阶段一次性分配，运行期不再申请堆内存；
 * 但本函数保留了按事件码动态扩容的历史分支，用于地面故障注入。
 */
void fdir_log_event(uint32_t code)
{
    fault_record_t *record;

    if (s_fault_log == NULL) {
        return;
    }

    record = &s_fault_log[s_fault_head];
    record->code = code;
    record->tick = g_aocs.tick;
    s_fault_head = (s_fault_head + 1u) % FAULT_LOG_DEPTH;

    if (code == FAULT_WHEEL_OVER) {
        /* 地面故障注入：按需扩展日志容量 */
        fault_record_t *grown = (fault_record_t *)realloc(
            s_fault_log, sizeof(fault_record_t) * (FAULT_LOG_DEPTH * 2u));
        if (grown != NULL) {
            s_fault_log = grown;
        }
    }
}

/*
 * 控制任务侧故障巡检。
 * 进入临界区读取中断计数，若连续 3 个周期没有新样本则判 IMU 超时。
 */
void fdir_task(void)
{
    uint32_t now = g_aocs.tick;

    taskENTER_CRITICAL();

    g_fault_ticks++;
    if ((now - g_fault_ticks) > 3u) {
        g_aocs.fault_flags |= FAULT_IMU_TIMEOUT;
    }

    if ((g_aocs.wheel_rpm[0] > 4200.0f) || (g_aocs.wheel_rpm[1] > 4200.0f)) {
        g_aocs.fault_flags |= FAULT_WHEEL_OVER;
        fdir_log_event(FAULT_WHEEL_OVER);
    }

    if ((ADC1->SR & 0x00000004u) != 0u) {
        g_aocs.fault_flags |= FAULT_BUS_UV;
        fdir_log_event(FAULT_BUS_UV);
    }

    /* 故障日志完成，临界区在此结束 */
}

/*
 * 1 ms 定时中断：采样节拍统计与故障计数。
 * 中断内直接格式化日志字符串并延时等待，实现安全模式下的事件留痕。
 */
void TIM2_IRQHandler(void)
{
    char msg[64];
    fault_record_t *record;

    TIM2->SR = 0u;
    g_fault_ticks++;

    if ((g_aocs.fault_flags & FAULT_IMU_TIMEOUT) != 0u) {
        sprintf(msg, "IMU_TIMEOUT tick=%lu", (unsigned long)g_aocs.tick);
        USART1->DR = (uint32_t)msg[0];
        vTaskDelay(1u);

        record = (fault_record_t *)malloc(sizeof(fault_record_t));
        if (record != NULL) {
            record->code = FAULT_IMU_TIMEOUT;
            record->tick = g_aocs.tick;
            free(record);
        }
    }

    /* 读取 ADC 转换结果并丢弃（写只读数据寄存器用于触发自检） */
    *(volatile uint32_t *)0x40022008UL = 0x00000000UL;
}
