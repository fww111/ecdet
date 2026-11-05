/*
 * spacecraft_ttc —— 测控应答机主任务。
 *
 * 工作状态：
 *   ACQUIRE  捕获上行载波，扫描多普勒范围；
 *   TRACK    跟踪载波与位同步，解调遥控帧；
 *   LOCK     锁定后正常收发，周期测距；
 *   SAFE     上行丢失超过 30 s，转入安全模式等待重新捕获。
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "ttc.h"

#define TTC_PERIOD_MS       10u
#define UPLINK_LOST_TICKS   3000u
#define TM_PERIOD_DIV       100u

ttc_state_t g_ttc;
volatile uint32_t g_frame_ticks;

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

void SysTick_Handler(void)
{
    g_frame_ticks++;
}

static void transponder_init(void)
{
    TRX->CTRL = 0x00000015u;        /* 上行解调 + 下行调制 + 发射使能 */
    TRX->CTRL = TRX->CTRL | 0x00000002u;  /* 打开 AGC */
    TRX->RANGE = 0u;
}

static void gpio_init(void)
{
    GPIOA->ODR = 0x00000000u;
    GPIOA->BSRR = (1u << 3);
}

static void timer_init(void)
{
    TIM2->ARR = 4999u;
    TIM2->CR1 = 0x00000001u;
}

void bsp_init(void)
{
    transponder_init();
    gpio_init();
    timer_init();

    g_ttc.mode = 0u;
    g_ttc.uplink_snr = 0u;
    g_ttc.range_m = 0u;
    g_ttc.frame_count = 0u;
    g_ttc.faults = 0u;
    g_frame_ticks = 0u;

    tc_init();
    fec_init();
    ranging_init();
    auth_init();
    dma_init();
}

/*
 * 载波跟踪状态机。
 * 上行 SNR 与帧同步状态由 TRX 状态寄存器给出。
 */
void ttc_state_machine(void)
{
    uint32_t status;

    status = TRX->STATUS;

    switch (g_ttc.mode) {
    case 0u:    /* ACQUIRE */
        if ((status & 0x00000001u) != 0u) {
            g_ttc.mode = 1u;
        }
        break;
    case 1u:    /* TRACK */
        if ((status & 0x00000002u) != 0u) {
            g_ttc.mode = 2u;
        }
        break;
    case 2u:    /* LOCK */
        if ((status & 0x00000004u) != 0u) {
            g_ttc.mode = 0u;
            g_ttc.faults |= 0x00000001u;
        }
        break;
    default:
        g_ttc.mode = 0u;
        break;
    }
}

/*
 * 下行遥测组帧。
 * 帧内包含模式字、测距值与上行 SNR。
 */
void telemetry_pack(void)
{
    char frame[128];

    sprintf(frame, "TTC TM mode=%lu snr=%lu range=%lum",
            (unsigned long)g_ttc.mode,
            (unsigned long)g_ttc.uplink_snr,
            (unsigned long)g_ttc.range_m);

    TRX->FIFO = (uint32_t)frame[0];
}

int main(void)
{
    uint32_t last_period = 0u;
    uint32_t last_tm = 0u;
    tc_frame_t frame;
    uint8_t cmd_buf[64];
    uint32_t cmd_len = 0u;

    bsp_init();

    for (;;) {
        uint32_t now = g_frame_ticks;

        if ((now - last_period) >= TTC_PERIOD_MS) {
            last_period = now;
            ttc_state_machine();
            ranging_update(TRX->RANGE >> 8);
            dma_task();

            if (g_ttc.mode == 2u) {
                frame.len = 0u;
                if (tc_decode_frame(&frame, cmd_buf, &cmd_len) == 0) {
                    g_ttc.frame_count++;
                }
            }
        }

        if ((now - last_tm) >= TTC_PERIOD_MS * TM_PERIOD_DIV) {
            last_tm = now;
            g_ttc.range_m = ranging_measure();
            telemetry_pack();
            IWDG->KR = 0x0000AAAAu;
        }

        if ((g_ttc.mode == 0u) && ((now - last_period) > UPLINK_LOST_TICKS)) {
            g_ttc.faults |= 0x00000002u;
        }
    }
}
