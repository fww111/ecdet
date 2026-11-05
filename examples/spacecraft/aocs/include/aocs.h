/*
 * spacecraft_aocs —— 星载姿态与轨道控制计算机（AOCS/GNC）公共接口。
 *
 * 本样例模拟一颗三轴稳定对地观测卫星的姿轨控分系统：
 *   - IMU 通过 SPI 周期采样，EXTI 外部中断触发采样完成；
 *   - 星敏感器/陀螺组合进行姿态确定，四元数递推；
 *   - 反作用飞轮三轴 PID 控制与饱和卸载；
 *   - J2 摄动下的开普勒轨道递推；
 *   - 故障检测与隔离（FDDI）、看门狗喂狗与安全模式切换。
 *
 * 平台抽象：SPC3000 星载控制 SoC（Cortex-M7 内核 + 航天级外设），
 * 寄存器语义由同目录 SPC3000.svd 描述，供 ECDET 的 MMIO 权限检查使用。
 * 所有外设结构体偏移与 SVD 的 addressOffset 一一对应。
 */
#ifndef AOCS_H
#define AOCS_H

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/* SPC3000 外设寄存器模型                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    volatile uint32_t RESERVED0[4];   /* 0x00..0x0F */
    volatile uint32_t IDR;            /* 0x10 只读：输入电平 */
    volatile uint32_t ODR;            /* 0x14 读写：输出电平 */
    volatile uint32_t BSRR;           /* 0x18 只写：原子置位/复位 */
} GPIO_TypeDef;

typedef struct {
    volatile uint32_t SR;             /* 0x00 只读：转换状态 */
    volatile uint32_t CR;             /* 0x04 读写：控制 */
    volatile uint32_t DR;             /* 0x08 只读：转换结果 */
} ADC_TypeDef;

typedef struct {
    volatile uint32_t CR1;            /* 0x00 读写：SPI 控制 */
    volatile uint32_t RESERVED0;      /* 0x04 */
    volatile uint32_t SR;             /* 0x08 只读：状态 */
    volatile uint32_t DR;             /* 0x0C 读写：收发数据 */
} SPI_TypeDef;

typedef struct {
    volatile uint32_t SR;             /* 0x00 只读：串口状态 */
    volatile uint32_t DR;             /* 0x04 读写：收发数据 */
    volatile uint32_t CR1;            /* 0x08 读写：控制 */
} USART_TypeDef;

typedef struct {
    volatile uint32_t CR1;            /* 0x00 读写 */
    volatile uint32_t RESERVED0[3];   /* 0x04..0x0F */
    volatile uint32_t SR;             /* 0x10 只读 */
    volatile uint32_t RESERVED1[4];   /* 0x14..0x23 */
    volatile uint32_t CNT;            /* 0x24 只读 */
    volatile uint32_t RESERVED2;      /* 0x28 */
    volatile uint32_t ARR;            /* 0x2C 读写 */
} TIM_TypeDef;

typedef struct {
    volatile uint32_t KR;             /* 0x00 只写：喂狗密钥 */
    volatile uint32_t PR;             /* 0x04 读写：预分频 */
    volatile uint32_t SR;             /* 0x08 只读：状态 */
} IWDG_TypeDef;

typedef struct {
    volatile uint32_t TR;             /* 0x00 只读：时间计数 */
    volatile uint32_t DR;             /* 0x04 只读：日期计数 */
    volatile uint32_t CR;             /* 0x08 读写：控制 */
} RTC_TypeDef;

typedef struct {
    volatile uint32_t MCR;            /* 0x00 读写：模式控制 */
    volatile uint32_t MSR;            /* 0x04 只读：模式状态 */
    volatile uint32_t TSR;            /* 0x08 只读：发送状态 */
    volatile uint32_t RFR;            /* 0x0C 只读：接收 FIFO */
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
#define SPI1              ((SPI_TypeDef *) SPI1_BASE)
#define USART1            ((USART_TypeDef *) USART1_BASE)
#define TIM2              ((TIM_TypeDef *) TIM2_BASE)
#define IWDG              ((IWDG_TypeDef *) IWDG_BASE)
#define RTC               ((RTC_TypeDef *) RTC_BASE)
#define CAN1              ((CAN_TypeDef *) CAN1_BASE)

/* ------------------------------------------------------------------ */
/* 实时操作系统（实际工程为 FreeRTOS，本项目内联最小桩函数）           */
/* ------------------------------------------------------------------ */

void taskENTER_CRITICAL(void);
void taskEXIT_CRITICAL(void);
void vTaskDelay(uint32_t ticks);
void vTaskDelayUntil(uint32_t *prev, uint32_t inc);
void xSemaphoreTake(void *sem, uint32_t timeout);
void xSemaphoreGive(void *sem);
void xSemaphoreGiveFromISR(void *sem, int32_t *woken);
void xQueueSend(void *queue, const void *item, uint32_t timeout);

/* ------------------------------------------------------------------ */
/* 基础数据类型                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    float x;
    float y;
    float z;
} vec3_t;

typedef struct {
    float q[4];             /* q0(qw), q1(qx), q2(qy), q3(qz) */
    float rate[3];          /* 本体系角速度 rad/s */
    float wheel_rpm[3];     /* 反作用轮转速 */
    uint32_t mode;          /* 当前控制模式 */
    uint32_t fault_flags;   /* 故障位图 */
    uint32_t tick;          /* 控制周期计数 */
} aocs_state_t;

typedef struct {
    float kp;
    float ki;
    float kd;
    float integral[3];
    float prev_err[3];
    float limit;
} pid_t;

typedef struct {
    unsigned rate_mode : 3;     /* 0..4 有效 */
    unsigned wheel_en : 1;
    unsigned safe_mode : 1;
    unsigned mlc_en : 1;
} aocs_ctrl_reg_t;

typedef struct {
    uint8_t axis : 2;           /* 轴编号 0..2 */
    uint8_t sign : 1;
} imu_axis_map_t;

enum {
    AOCS_MODE_OFF = 0u,
    AOCS_MODE_RATE_DAMP = 1u,
    AOCS_MODE_NORMAL = 2u,
    AOCS_MODE_SAFE = 3u,
    AOCS_MODE_ORBIT = 4u
};

/* 共享状态：由初始化阶段写入，任务与中断并发访问（样例缺陷所在） */
extern aocs_state_t g_aocs;
extern uint32_t g_imu_raw;
extern volatile uint32_t g_imu_events;
extern volatile uint32_t g_fault_ticks;

/* IMU 采样中断标志（EXTI0 触发） */
void imu_exti_irq_handler(void);

/* ------------------------------------------------------------------ */
/* 模块接口                                                            */
/* ------------------------------------------------------------------ */

void bsp_init(void);
void mode_manager(void);
void telemetry_pack(void);

void imu_init(void);
void imu_bus_selftest(void);
void imu_apply_config(void);
uint16_t imu_convert_raw(uint32_t raw);
float imu_read_rate(uint32_t axis);
void EXTI0_IRQHandler(void);

void attitude_init(void);
void attitude_update(float dt);
void attitude_normalize(aocs_state_t *st, uint8_t depth);
float attitude_determinant(void);

void wheel_init(void);
void wheel_control(float dt);
void wheel_unload(uint32_t axis);
uint32_t wheel_mode_state(uint32_t mode);

void orbit_init(void);
void orbit_propagate(double dt, double *out_state);
double *orbit_work_buffer(void);
void orbit_copy_state(double *dst);

void fdir_init(void);
void fdir_task(void);
void TIM2_IRQHandler(void);
void fdir_log_event(uint32_t code);

#endif /* AOCS_H */
