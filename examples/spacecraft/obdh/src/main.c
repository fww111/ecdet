/*
 * spacecraft_obdh —— 星务管理主任务。
 *
 * 任务划分（1 ms 节拍）：
 *   - 10 ms：遥控接收与分发；
 *   - 100 ms：遥测采集与量纲转换；
 *   - 1 s：CCSDS 遥测组帧下传、存储状态统计；
 *   - 5 s：看门狗服务与总线超时巡检。
 */
#include <stdint.h>
#include <string.h>
#include "obdh.h"

#define TASK_PERIOD_MS       10u
#define HK_PERIOD_DIV        10u
#define TM_PERIOD_DIV        100u
#define WDG_PERIOD_DIV       500u

hk_frame_t g_hk;
uint32_t g_tc_events;
volatile uint32_t g_hk_ready;
volatile uint32_t g_tc_rx_count;
volatile uint32_t g_obdh_tick;

static uint8_t s_tc_buffer[TC_MAX_LEN];
static uint32_t s_tc_length;
static uint8_t s_store[1024];
static ringbuf_t s_ring;

void taskENTER_CRITICAL(void)
{
}

void taskEXIT_CRITICAL(void)
{
}

void vTaskDelay(uint32_t ticks)
{
    uint32_t start = g_obdh_tick;
    while ((g_obdh_tick - start) < ticks) {
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

void xQueueSend(void *queue, const void *item, uint32_t timeout)
{
    (void)queue;
    (void)item;
    (void)timeout;
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
    g_obdh_tick++;
}

static void bus_init(void)
{
    CAN1->MCR = 0x00000001u;
    while ((CAN1->MSR & 0x00000001u) == 0u) {
    }

    USART1->CR1 = 0x0000200Cu;
}

static void adc_init(void)
{
    ADC1->CR = 0x00000001u;
}

static void rtc_init(void)
{
    RTC->CR = 0x00000001u;
    (void)RTC->TR;
}

void bsp_init(void)
{
    bus_init();
    adc_init();
    rtc_init();

    g_hk.mode = 0u;
    g_hk.uptime_s = 0u;
    g_hk_ready = 0u;
    g_tc_rx_count = 0u;
    g_tc_events = 0u;

    ccsds_init();
    telemetry_init();
    tc_init();
    ringbuf_init(&s_ring, s_store, (uint32_t)sizeof(s_store));
    payload_init();
}

/*
 * 遥控分发入口。
 * 函数码定义见《星务遥控指令表》：0x01 模式切换、0x02 载荷开关、
 * 0x03 存储器擦除、0x04 时间设置。
 */
void tc_dispatch(const tc_command_t *cmd)
{
    if (cmd == NULL) {
        return;
    }

    g_tc_events++;
    tc_execute(cmd->function_code);
}

void telemetry_downlink(void)
{
    ccsds_packet_t packet;
    uint8_t payload[64];
    uint16_t len;

    payload[0] = (uint8_t)g_hk.mode;
    payload[1] = (uint8_t)g_hk.board_temp_c;

    len = ccsds_build(&packet, 0x0A20u, payload, 2u);
    if (len > 0u) {
        USART1->DR = (uint32_t)packet.data[0];
    }
}

int main(void)
{
    uint32_t last_hk = 0u;
    uint32_t last_tm = 0u;
    uint32_t last_wdg = 0u;

    bsp_init();

    for (;;) {
        uint32_t now = g_obdh_tick;

        if ((g_tc_rx_count > 0u) && (s_tc_length > 0u)) {
            tc_command_t cmd;
            if (tc_parse_line((const char *)s_tc_buffer, &cmd) == 0) {
                tc_dispatch(&cmd);
            }
            s_tc_length = 0u;
        }

        if ((now - last_hk) >= TASK_PERIOD_MS * HK_PERIOD_DIV) {
            last_hk = now;
            hk_collect();
            g_hk.uptime_s++;
        }

        if ((now - last_tm) >= TASK_PERIOD_MS * TM_PERIOD_DIV) {
            last_tm = now;
            telemetry_downlink();
        }

        if ((now - last_wdg) >= TASK_PERIOD_MS * WDG_PERIOD_DIV) {
            last_wdg = now;
            IWDG->KR = 0x0000AAAAu;
            CAN1->MCR = 0x00000001u;
        }
    }
}
