/*
 * spacecraft_ttc —— 测控应答机（TT&C）公共接口。
 *
 * 场景：卫星测控分系统，完成
 *   - 上行遥控帧捕获、位同步、CRC 校验与指令解码；
 *   - 下行遥测帧编码、RS(255,223) 前向纠错与发射；
 *   - 测距音相关处理与距离解算；
 *   - 遥控注入鉴权与防重放；
 *   - DMA 收发描述符管理。
 *
 * 平台：SPC3000 星载 SoC + TRX 应答机基带寄存器，
 * 寄存器语义见同目录 SPC3000.svd。
 */
#ifndef TTC_H
#define TTC_H

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/* SPC3000 / TRX 寄存器模型                                            */
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
    volatile uint32_t MCR;
    volatile uint32_t MSR;
    volatile uint32_t TSR;
    volatile uint32_t RFR;
} CAN_TypeDef;

typedef struct {
    volatile uint32_t CTRL;         /* 0x00 读写：调制/解调/发射使能 */
    volatile uint32_t STATUS;       /* 0x04 只读：锁定/失锁/帧同步 */
    volatile uint32_t FIFO;         /* 0x08 读写：基带收发 FIFO */
    volatile uint32_t AGC;          /* 0x0C 只读：自动增益控制字 */
    volatile uint32_t RANGE;        /* 0x10 读写：测距计数 */
} TRX_TypeDef;

#define PERIPH_BASE       0x40000000UL
#define GPIOA_BASE        (PERIPH_BASE + 0x00020000UL)
#define ADC_BASE          (PERIPH_BASE + 0x00022000UL)
#define USART1_BASE       (PERIPH_BASE + 0x00024000UL)
#define TIM2_BASE         (PERIPH_BASE + 0x00025000UL)
#define IWDG_BASE         (PERIPH_BASE + 0x00026000UL)
#define CAN1_BASE         (PERIPH_BASE + 0x00028000UL)
#define TRX_BASE          (PERIPH_BASE + 0x0002A000UL)

#define GPIOA             ((GPIO_TypeDef *) GPIOA_BASE)
#define ADC1              ((ADC_TypeDef *) ADC_BASE)
#define USART1            ((USART_TypeDef *) USART1_BASE)
#define TIM2              ((TIM_TypeDef *) TIM2_BASE)
#define IWDG              ((IWDG_TypeDef *) IWDG_BASE)
#define CAN1              ((CAN_TypeDef *) CAN1_BASE)
#define TRX               ((TRX_TypeDef *) TRX_BASE)

/* ------------------------------------------------------------------ */
/* 最小 RTOS 桩                                                        */
/* ------------------------------------------------------------------ */

void taskENTER_CRITICAL(void);
void taskEXIT_CRITICAL(void);
void vTaskDelay(uint32_t ticks);
void xSemaphoreTake(void *sem, uint32_t timeout);
void xSemaphoreGive(void *sem);
void xSemaphoreGiveFromISR(void *sem, int32_t *woken);

/* ------------------------------------------------------------------ */
/* 测控数据结构                                                        */
/* ------------------------------------------------------------------ */

#define TC_FRAME_MAX        192u
#define TM_FRAME_MAX        256u
#define FEC_BLOCK_MAX       255u
#define FEC_DATA_MAX        223u

typedef struct {
    uint32_t mode;
    uint32_t uplink_snr;
    uint32_t range_m;
    uint32_t frame_count;
    uint32_t faults;
} ttc_state_t;

typedef struct {
    uint8_t  raw[TC_FRAME_MAX];
    uint16_t len;
    uint32_t timestamp;
} tc_frame_t;

typedef struct {
    uint32_t address;
    uint32_t length;
    uint32_t control;
} dma_desc_t;

typedef struct {
    uint8_t  block[FEC_BLOCK_MAX];
    uint16_t data_len;
    uint8_t  parity[32];
} fec_block_t;

extern ttc_state_t g_ttc;
extern uint32_t g_dma_done;
extern volatile uint32_t g_dma_count;
extern volatile uint32_t g_frame_ticks;

/* ------------------------------------------------------------------ */
/* 模块接口                                                            */
/* ------------------------------------------------------------------ */

void bsp_init(void);
void ttc_state_machine(void);
void telemetry_pack(void);

void tc_init(void);
int tc_decode_frame(const tc_frame_t *frame, uint8_t *cmd_buf, uint32_t *cmd_len);
void tc_execute(uint32_t opcode);
void tc_report(char *name);

void fec_init(void);
int fec_encode(const uint8_t *data, uint16_t len, uint8_t *parity);
int fec_decode(uint8_t *block, uint16_t len);
uint8_t fec_gf_mul(uint8_t a, uint8_t b);
void fec_selftest(void);

void ranging_init(void);
void ranging_update(uint32_t tone_cycles);
uint32_t ranging_measure(void);
int32_t ranging_calibrate(int32_t measured_m);

void auth_init(void);
int auth_verify(const char *token);
void auth_generate_tag(char *dst, uint32_t len);

void dma_init(void);
void dma_start(uint32_t address, uint32_t length);
void USART1_IRQHandler(void);
void DMA1_Channel1_IRQHandler(void);
void dma_task(void);

#endif /* TTC_H */
