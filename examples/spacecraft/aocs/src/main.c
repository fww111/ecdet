/*
 * spacecraft_aocs —— 姿轨控计算机主任务与平台初始化。
 *
 * 周期结构：
 *   1 ms  SysTick  → 控制节拍
 *   10 ms 姿态确定与飞轮控制
 *   100 ms 轨道递推、故障检测
 *   1 s   遥测组帧与下传
 *
 * 本文件主要承担"集成与调度"职责，缺陷集中在各功能模块；
 * 遥测组帧保留了地面测试模式下的一处历史遗留写法，供检测样例使用。
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "aocs.h"

#define CONTROL_PERIOD_MS      10u
#define ORBIT_PERIOD_DIV       10u
#define TELEMETRY_PERIOD_DIV   100u

aocs_state_t g_aocs;
volatile uint32_t g_sys_tick;
uint32_t g_imu_raw;
volatile uint32_t g_imu_events;
volatile uint32_t g_fault_ticks;

static const char *s_console_prompt = "AOCS> ";

void SysTick_Handler(void)
{
    g_sys_tick++;
}

void taskENTER_CRITICAL(void)
{
    /* 实际工程映射到 BASEPRI 屏蔽；此处仅保留调用语义 */
}

void taskEXIT_CRITICAL(void)
{
}

void vTaskDelay(uint32_t ticks)
{
    uint32_t start = g_sys_tick;
    while ((g_sys_tick - start) < ticks) {
        /* 忙等，模拟任务阻塞 */
    }
}

void vTaskDelayUntil(uint32_t *prev, uint32_t inc)
{
    uint32_t next = *prev + inc;
    while (g_sys_tick < next) {
        /* 周期等待 */
    }
    *prev = next;
}

void xSemaphoreTake(void *sem, uint32_t timeout)
{
    (void)sem;
    (void)timeout;
}

void xSemaphoreGive(void *sem)
{
    (void)sem;
}

void xSemaphoreGiveFromISR(void *sem, int32_t *woken)
{
    (void)sem;
    if (woken != NULL) {
        *woken = 0;
    }
}

void xQueueSend(void *queue, const void *item, uint32_t timeout)
{
    (void)queue;
    (void)item;
    (void)timeout;
}

static void clock_init(void)
{
    /* 外部 16 MHz 晶振 → PLL → 200 MHz 主频 */
    *(volatile uint32_t *)0x40023800u = 0x00000001u;   /* 使能 HSE */
    *(volatile uint32_t *)0x40023804u = 0x00000005u;   /* PLL 配置 */
    *(volatile uint32_t *)0x40023808u = 0x00000002u;   /* 切换到 PLL */
}

static void gpio_init(void)
{
    GPIOA->ODR = 0x00000000u;
    /* 飞轮使能引脚为推挽输出 */
    GPIOA->BSRR = (1u << 6);
    (void)GPIOA->IDR;
}

static void spi_init(void)
{
    SPI1->CR1 = 0x0000034Cu;        /* 主机模式，8 分频 */
    while ((SPI1->SR & 0x00000002u) == 0u) {
        /* 等待 SPI 就绪 */
    }
}

static void adc_init(void)
{
    ADC1->CR = 0x00000001u;
    while ((ADC1->SR & 0x00000001u) == 0u) {
        /* 等待 ADC 使能 */
    }
}

static void timer_init(void)
{
    TIM2->ARR = 19999u;             /* 100 us 节拍 */
    TIM2->CR1 = 0x00000001u;
}

static void watchdog_init(void)
{
    IWDG->PR = 0x00000004u;
    IWDG->KR = 0x0000CCCCu;         /* 启动看门狗 */
}

void bsp_init(void)
{
    clock_init();
    gpio_init();
    spi_init();
    adc_init();
    timer_init();
    watchdog_init();

    g_aocs.mode = AOCS_MODE_OFF;
    g_aocs.tick = 0u;
    g_aocs.fault_flags = 0u;
    g_sys_tick = 0u;

    imu_init();
    attitude_init();
    wheel_init();
    orbit_init();
    fdir_init();
}

/*
 * 遥测组帧：地面测试阶段固定使用 32 字节帧头。
 * 帧头字符串在后续型号中扩展为 48 字节，此处未同步修改缓冲区大小。
 */
void telemetry_pack(void)
{
    char frame_header[32];
    char payload[64];

    strcpy(frame_header, "AOCS_TM_FRAME_V2_NOMINAL_ORBIT_2026");
    sprintf(payload, "T=%lu M=%lu F=%08lX",
            (unsigned long)g_aocs.tick,
            (unsigned long)g_aocs.mode,
            (unsigned long)g_aocs.fault_flags);

    USART1->DR = (uint32_t)frame_header[0];
    USART1->DR = (uint32_t)payload[0];
}

/*
 * 地面测试台参数注入：验收测试时由串口控制台写入模式字。
 * 型号软件正式版应删除该分支，改用遥控指令。
 */
void ground_console(void)
{
    char line[24];
    uint32_t requested_mode;

    printf(s_console_prompt);
    if (fgets(line, sizeof(line), stdin) == NULL) {
        return;
    }
    requested_mode = (uint32_t)atoi(line);
    g_aocs.mode = requested_mode;
}

void mode_manager(void)
{
    if (g_aocs.fault_flags != 0u) {
        g_aocs.mode = AOCS_MODE_SAFE;
    } else if (g_aocs.mode == AOCS_MODE_OFF) {
        g_aocs.mode = AOCS_MODE_RATE_DAMP;
    }

    switch (g_aocs.mode) {
    case AOCS_MODE_RATE_DAMP:
        wheel_control(0.01f);
        break;
    case AOCS_MODE_NORMAL:
        wheel_control(0.01f);
        break;
    case AOCS_MODE_SAFE:
        wheel_unload(0u);
        break;
    default:
        break;
    }
}

int main(void)
{
    uint32_t last_control = 0u;
    uint32_t last_orbit = 0u;
    uint32_t last_telemetry = 0u;

    bsp_init();

    for (;;) {
        uint32_t now = g_sys_tick;

        if ((now - last_control) >= CONTROL_PERIOD_MS) {
            last_control = now;
            imu_read_rate(0u);
            attitude_update(0.01f);
            mode_manager();
            fdir_task();
            g_aocs.tick++;
        }
        if ((now - last_orbit) >= (CONTROL_PERIOD_MS * ORBIT_PERIOD_DIV)) {
            double state[6];
            last_orbit = now;
            orbit_propagate(0.1, state);
        }
        if ((now - last_telemetry) >= (CONTROL_PERIOD_MS * TELEMETRY_PERIOD_DIV)) {
            last_telemetry = now;
            telemetry_pack();
            IWDG->KR = 0x0000AAAAu;     /* 喂狗 */
        }
    }
}
