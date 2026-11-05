/*
 * spacecraft_obdh —— 星务管理单元（OBDH）公共接口。
 *
 * 场景：一颗低轨遥感卫星的星务计算机，负责：
 *   - CCSDS 遥测包组帧、虚拟信道调度与下行；
 *   - 遥控指令注入、校验、分发到各分系统；
 *   - 星上遥测采集（温度、电压、电流、存储状态）；
 *   - 大容量存储器环形缓冲与载荷数据路由；
 *   - 总线（CAN/RS-485）超时监控与看门狗管理。
 *
 * 平台：SPC3000 星载 SoC，寄存器语义见同目录 SPC3000.svd。
 */
#ifndef OBDH_H
#define OBDH_H

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/* SPC3000 外设寄存器模型                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    volatile uint32_t RESERVED0[4];
    volatile uint32_t IDR;
    volatile uint32_t ODR;
    volatile uint32_t BSRR;
} GPIO_TypeDef;

typedef struct {
    volatile uint32_t SR;
    volatile uint32_t CR;
    volatile uint32_t DR;
} ADC_TypeDef;

typedef struct {
    volatile uint32_t SR;
    volatile uint32_t DR;
    volatile uint32_t CR1;
} USART_TypeDef;

typedef struct {
    volatile uint32_t CR1;
    volatile uint32_t RESERVED0[3];
    volatile uint32_t SR;
    volatile uint32_t RESERVED1[4];
    volatile uint32_t CNT;
    volatile uint32_t RESERVED2;
    volatile uint32_t ARR;
} TIM_TypeDef;

typedef struct {
    volatile uint32_t KR;
    volatile uint32_t PR;
    volatile uint32_t SR;
} IWDG_TypeDef;

typedef struct {
    volatile uint32_t TR;
    volatile uint32_t DR;
    volatile uint32_t CR;
} RTC_TypeDef;

typedef struct {
    volatile uint32_t MCR;
    volatile uint32_t MSR;
    volatile uint32_t TSR;
    volatile uint32_t RFR;
} CAN_TypeDef;

#define PERIPH_BASE       0x40000000UL
#define GPIOA_BASE        (PERIPH_BASE + 0x00020000UL)
#define ADC_BASE          (PERIPH_BASE + 0x00022000UL)
#define SPI1_BASE         (PERIPH_BASE + 0x00023000UL)
#define USART1_BASE       (PERIPH_BASE + 0x00024000UL)
#define TIM2_BASE         (PERIPH_BASE + 0x00025000UL)
#define IWDG_BASE         (PERIPH_BASE + 0x00026000UL)
#define RTC_BASE          (PERIPH_BASE + 0x00027000UL)
#define CAN1_BASE         (PERIPH_BASE + 0x00028000UL)

#define GPIOA             ((GPIO_TypeDef *) GPIOA_BASE)
#define ADC1              ((ADC_TypeDef *) ADC_BASE)
#define USART1            ((USART_TypeDef *) USART1_BASE)
#define TIM2              ((TIM_TypeDef *) TIM2_BASE)
#define IWDG              ((IWDG_TypeDef *) IWDG_BASE)
#define RTC               ((RTC_TypeDef *) RTC_BASE)
#define CAN1              ((CAN_TypeDef *) CAN1_BASE)

/* ------------------------------------------------------------------ */
/* 最小 RTOS 桩                                                        */
/* ------------------------------------------------------------------ */

void taskENTER_CRITICAL(void);
void taskEXIT_CRITICAL(void);
void vTaskDelay(uint32_t ticks);
void xSemaphoreTake(void *sem, uint32_t timeout);
void xSemaphoreGive(void *sem);
void xSemaphoreGiveFromISR(void *sem, int32_t *woken);
void xQueueSend(void *queue, const void *item, uint32_t timeout);
void xQueueSendFromISR(void *queue, const void *item, int32_t *woken);

/* ------------------------------------------------------------------ */
/* CCSDS 与星务数据结构                                                */
/* ------------------------------------------------------------------ */

#define CCSDS_MAX_PACKET    256u
#define CCSDS_HDR_LEN       6u
#define TC_MAX_LEN          128u
#define TM_FRAME_MAX        512u

typedef struct {
    uint16_t apid;
    uint16_t sequence;
    uint16_t length;
    uint8_t  data[CCSDS_MAX_PACKET];
} ccsds_packet_t;

typedef struct {
    uint16_t apid;
    uint16_t function_code;
    uint16_t data_len;
    uint8_t  data[TC_MAX_LEN];
} tc_command_t;

typedef struct {
    uint32_t bus_voltage_mv;
    int16_t  board_temp_c;
    int16_t  battery_temp_c;
    uint32_t solar_current_ma;
    uint32_t storage_free_kb;
    uint32_t mode;
    uint32_t uptime_s;
} hk_frame_t;

typedef struct {
    uint8_t *buffer;
    uint32_t capacity;
    uint32_t head;
    uint32_t tail;
    uint32_t count;
} ringbuf_t;

/* 共享状态 */
extern hk_frame_t g_hk;
extern uint32_t g_tc_events;
extern volatile uint32_t g_hk_ready;
extern volatile uint32_t g_tc_rx_count;

/* ------------------------------------------------------------------ */
/* 模块接口                                                            */
/* ------------------------------------------------------------------ */

void bsp_init(void);
void hk_collect(void);
void telemetry_downlink(void);
void tc_dispatch(const tc_command_t *cmd);
void TIM2_IRQHandler(void);

void ccsds_init(void);
uint16_t ccsds_build(ccsds_packet_t *packet, uint16_t apid,
                     const uint8_t *payload, uint16_t len);
int ccsds_parse(const uint8_t *raw, uint16_t raw_len, ccsds_packet_t *out);
uint16_t ccsds_vc_schedule(uint16_t vc_id);

uint16_t crc16_ccitt(const uint8_t *data, uint32_t len);
uint16_t crc16_update(uint16_t seed, uint8_t byte);
void crc_selftest(void);

void telemetry_init(void);
void hk_convert(uint32_t raw, hk_frame_t *frame);
void hk_format_name(char *dst, uint32_t channel);
void USART1_IRQHandler(void);

void tc_init(void);
int tc_parse_line(const char *line, tc_command_t *cmd);
void tc_execute(uint32_t function_code);
void tc_selftest(void);

void ringbuf_init(ringbuf_t *rb, uint8_t *storage, uint32_t capacity);
int ringbuf_push(ringbuf_t *rb, uint8_t byte);
int ringbuf_pop(ringbuf_t *rb, uint8_t *byte);
uint32_t ringbuf_used(const ringbuf_t *rb);
void ringbuf_stats(uint32_t depth);

void payload_init(void);
int payload_route(uint32_t payload_id, const uint8_t *data, uint32_t len);
int payload_authenticate(const char *token);
void payload_cleanup(void);

#endif /* OBDH_H */
