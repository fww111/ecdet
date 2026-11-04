/*
 * spacecraft_eps —— 电源控制单元（EPS/PCU）公共接口。
 *
 * 场景：卫星电源分系统，包含
 *   - 太阳阵最大功率点跟踪（MPPT，扰动观察法）；
 *   - 锂离子蓄电池充放电管理、SOC 估算与过放保护；
 *   - 一次母线配电、负载优先级与欠压卸载；
 *   - 星上加热器 PWM 温控；
 *   - 模拟量采集中断（ADC）与保护跳闸。
 *
 * 平台：SPC3000 星载 SoC，电源专用寄存器 PWR 定义见 SPC3000.svd。
 */
#ifndef EPS_H
#define EPS_H

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

typedef struct {
    volatile uint32_t CTRL;         /* 0x00 读写：主备份选择、MPPT 使能 */
    volatile uint32_t STATUS;       /* 0x04 只读：母线/电池状态 */
    volatile uint32_t FLAGS;        /* 0x08 只读：保护标志 */
    volatile uint32_t LATCH;        /* 0x0C 只写：标志清除 */
} PWR_TypeDef;

#define PERIPH_BASE       0x40000000UL
#define GPIOA_BASE        (PERIPH_BASE + 0x00020000UL)
#define ADC_BASE          (PERIPH_BASE + 0x00022000UL)
#define USART1_BASE       (PERIPH_BASE + 0x00024000UL)
#define TIM2_BASE         (PERIPH_BASE + 0x00025000UL)
#define IWDG_BASE         (PERIPH_BASE + 0x00026000UL)
#define RTC_BASE          (PERIPH_BASE + 0x00027000UL)
#define CAN1_BASE         (PERIPH_BASE + 0x00028000UL)
#define PWR_BASE          (PERIPH_BASE + 0x00029000UL)

#define GPIOA             ((GPIO_TypeDef *) GPIOA_BASE)
#define ADC1              ((ADC_TypeDef *) ADC_BASE)
#define USART1            ((USART_TypeDef *) USART1_BASE)
#define TIM2              ((TIM_TypeDef *) TIM2_BASE)
#define IWDG              ((IWDG_TypeDef *) IWDG_BASE)
#define RTC               ((RTC_TypeDef *) RTC_BASE)
#define CAN1              ((CAN_TypeDef *) CAN1_BASE)
#define PWR               ((PWR_TypeDef *) PWR_BASE)

/* ------------------------------------------------------------------ */
/* 最小 RTOS 桩                                                        */
/* ------------------------------------------------------------------ */

void taskENTER_CRITICAL(void);
void taskEXIT_CRITICAL(void);
void vTaskDelay(uint32_t ticks);
void xSemaphoreTake(void *sem, uint32_t timeout);
void xSemaphoreGive(void *sem);
void xSemaphoreGiveFromISR(void *sem, int32_t *woken);
void xQueueSendFromISR(void *queue, const void *item, int32_t *woken);

/* ------------------------------------------------------------------ */
/* 电源分系统数据结构                                                  */
/* ------------------------------------------------------------------ */

#define EPS_LOAD_COUNT      6u
#define EPS_HEATER_COUNT    4u

typedef struct {
    uint32_t mode;
    uint32_t bus_mv;
    uint32_t solar_ma;
    uint32_t load_ma;
    int16_t  battery_soc;
    uint32_t heater_duty[EPS_HEATER_COUNT];
    uint32_t faults;
} eps_state_t;

typedef struct {
    uint32_t last_power;
    uint32_t duty;
    uint32_t direction;
    uint32_t step;
} mppt_t;

typedef struct {
    uint32_t capacity_mah;
    int32_t  coulomb_uah;
    int32_t  cell_mv[8];
    uint32_t cell_count;
} battery_t;

typedef struct {
    uint8_t heater_id : 2;
    uint8_t channel : 3;
    uint8_t auto_mode : 1;
} heater_map_t;

typedef struct {
    unsigned heater_en : 4;
    unsigned bus_sel : 2;
    unsigned mppt_en : 1;
    unsigned reserved : 1;
} heater_ctrl_t;

extern eps_state_t g_eps;
extern uint32_t g_adc_raw;
extern volatile uint32_t g_adc_isr_count;
extern volatile uint32_t g_adc_ticks;

/* ------------------------------------------------------------------ */
/* 模块接口                                                            */
/* ------------------------------------------------------------------ */

void bsp_init(void);
void eps_mode_manager(void);
void telemetry_pack(void);

void mppt_init(void);
void mppt_step(void);
uint32_t mppt_duty(void);

void battery_init(void);
void battery_update(uint32_t dt_ms);
int16_t battery_soc_percent(void);
uint32_t battery_charge_limit(void);

void heater_init(void);
void heater_control(void);
void heater_set_duty(uint32_t channel, uint32_t duty);

void adc_isr_init(void);
void ADC1_2_IRQHandler(void);
void TIM2_IRQHandler(void);
void adc_task(void);

void protection_init(void);
void protection_check(void);
void protection_trip(uint32_t code);

#endif /* EPS_H */
