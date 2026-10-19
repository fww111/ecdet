/*
 * demo_rtos 主程序：裸机前后台架构。
 * 本文件为"基本干净"的参照代码，缺陷集中在 sensor.c / comm.c。
 */
#include <stdint.h>
#include "demo.h"

#define MAIN_LOOP_PERIOD_MS 100u

static volatile uint8_t s_tick_flag;

/* SysTick 中断服务程序（示例：CMSIS 风格命名） */
void SysTick_Handler(void)
{
    s_tick_flag = 1u;
}

int main(void)
{
    uint8_t idle_count = 0u;

    bsp_init();

    for (;;) {
        if (s_tick_flag != 0u) {
            s_tick_flag = 0u;
            (void)sensor_sample();
            comm_send_frame("tick");
            idle_count = 0u;
        } else {
            idle_count++;
        }
    }
    /* 不会到达 */
}
