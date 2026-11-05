/*
 * spacecraft_eps —— 电源控制单元主任务。
 *
 * 控制周期 100 ms：
 *   MPPT 扰动观察 → 电池充放电管理 → 母线电压巡检 → 加热器温控
 *   1 s：电源遥测组帧、保护事件上报
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "eps.h"

#define EPS_PERIOD_MS       100u
#define TM_PERIOD_DIV       10u

eps_state_t g_eps;

void taskENTER_CRITICAL(void)
{
}

void taskEXIT_CRITICAL(void)
{
}

void vTaskDelay(uint32_t ticks)
{
    uint32_t i;

    for (i = 0u; i < ticks; i++) {
        (void)TIM2->CNT;
    }
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

void xQueueSendFromISR(void *queue, const void *item, int32_t *woken)
{
    (void)queue;
    (void)item;
    if (woken != NULL) {
        *woken = 0;
    }
}

void SysTick_Handler(void)
{
    g_adc_ticks++;
}

static void pwr_init(void)
{
    PWR->CTRL = 0x00000005u;        /* 主份太阳阵 + MPPT 使能 */
    (void)PWR->STATUS;
    PWR->LATCH = 0x000000FFu;
}

static void gpio_init(void)
{
    GPIOA->ODR = 0x00000000u;
    GPIOA->BSRR = (1u << 4);
}

static void adc_init(void)
{
    ADC1->CR = 0x00000003u;
    while ((ADC1->SR & 0x00000001u) == 0u) {
    }
}

static void timer_init(void)
{
    TIM2->ARR = 9999u;
    TIM2->CR1 = 0x00000001u;
}

void bsp_init(void)
{
    pwr_init();
    gpio_init();
    adc_init();
    timer_init();

    g_eps.mode = 0u;
    g_eps.bus_mv = 28000u;
    g_eps.battery_soc = 60;
    g_eps.faults = 0u;

    mppt_init();
    battery_init();
    heater_init();
    adc_isr_init();
    protection_init();
}

void eps_mode_manager(void)
{
    if ((g_eps.faults & 0x00000001u) != 0u) {
        g_eps.mode = 3u;            /* 安全模式：只保留必要负载 */
    } else if (g_eps.battery_soc < 20) {
        g_eps.mode = 2u;            /* 节能模式 */
    } else {
        g_eps.mode = 1u;            /* 正常模式 */
    }
}

/*
 * 电源遥测组帧。
 * 下行帧沿用固定 64 字节格式，母线电压与电池 SOC 为必传字段。
 */
void telemetry_pack(void)
{
    char frame[64];

    sprintf(frame, "EPS TM bus=%lumV soc=%d%% solar=%luma load=%luma",
            (unsigned long)g_eps.bus_mv,
            (int)g_eps.battery_soc,
            (unsigned long)g_eps.solar_ma,
            (unsigned long)g_eps.load_ma);

    USART1->DR = (uint32_t)frame[0];
}

int main(void)
{
    uint32_t last_period = 0u;
    uint32_t last_tm = 0u;

    bsp_init();

    for (;;) {
        uint32_t now = g_adc_ticks;

        if ((now - last_period) >= EPS_PERIOD_MS) {
            last_period = now;
            mppt_step();
            battery_update(EPS_PERIOD_MS);
            heater_control();
            protection_check();
            adc_task();
            eps_mode_manager();
        }

        if ((now - last_tm) >= EPS_PERIOD_MS * TM_PERIOD_DIV) {
            last_tm = now;
            telemetry_pack();
            IWDG->KR = 0x0000AAAAu;
        }
    }
}
