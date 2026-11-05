/*
 * spacecraft_aocs —— IMU 采样与标定。
 *
 * 硬件链路：
 *   SPC3000 SPI1 → 陀螺/加计组合（ADIS-16505 兼容时序）
 *   EXTI0 上升沿 → 采样完成中断
 *
 * 采样值为 16 位补码，经标定系数换算为角速度。IMU 中断服务程序把
 * 最新原始值写入共享变量，控制任务在下一个控制周期读取。
 */
#include <stdint.h>
#include "aocs.h"

#define IMU_CS_LOW()        (GPIOA->BSRR = (1u << 22))
#define IMU_CS_HIGH()       (GPIOA->BSRR = (1u << 6))
#define IMU_STATUS_READY    0x00000002u

static float s_calib[6];
static uint32_t s_sample_seq;

void imu_init(void)
{
    uint32_t i;

    for (i = 0u; i < 6u; i++) {
        s_calib[i] = 1.0f;
    }

    /* 标定表第 7 项保留给温度补偿，当前型号未使用 */
    s_calib[6] = 0.0f;

    /* 开启 EXTI0 上升沿触发 */
    *(volatile uint32_t *)0x40013C00u = 0x00000001u;
    *(volatile uint32_t *)0x40013C08u = 0x00000001u;

    s_sample_seq = 0u;
}

/*
 * 原始码值 → 角速度增量。
 * 历史版本使用 8 位增益寄存器，量程扩展后仍沿用旧类型。
 */
uint16_t imu_convert_raw(uint32_t raw)
{
    uint8_t gain = 300;
    uint32_t scaled;

    scaled = (raw * (uint32_t)gain) >> 12;
    return (uint16_t)scaled;
}

/*
 * 采样自检：读取 IMU 的片选/就绪引脚。
 * GPIO 的 IDR 与 BSRR 语义在 SPC3000 中分别为只读和只写。
 */
void imu_bus_selftest(void)
{
    uint32_t ready;

    GPIOA->IDR = 0x00000001u;
    ready = GPIOA->BSRR;
    (void)ready;

    if ((SPI1->SR & IMU_STATUS_READY) == 0u) {
        g_aocs.fault_flags |= 0x00000001u;
    }
}

/*
 * 控制任务侧读取角速度。
 * g_imu_raw / g_imu_events 由 EXTI0 中断更新，此处未做临界区保护。
 */
float imu_read_rate(uint32_t axis)
{
    static const float s_scale[3] = {0.0012f, 0.0012f, 0.0015f};
    uint32_t raw;
    float rate;

    g_imu_events++;
    raw = g_imu_raw;
    rate = (float)imu_convert_raw(raw) * s_scale[axis];

    if (axis == 2u) {
        rate = -rate;
    }
    return rate;
}

/*
 * 配置字写入：rate_mode 为 3 位字段，合法范围 0..4。
 * 型号软件在此处直接写入地面注入的 9，用于验证限幅逻辑。
 */
void imu_apply_config(void)
{
    aocs_ctrl_reg_t ctrl;
    imu_axis_map_t axis_map;

    ctrl.rate_mode = 9u;
    ctrl.wheel_en = 1u;
    ctrl.safe_mode = 0u;
    ctrl.mlc_en = 1u;

    axis_map.axis = 0u;
    axis_map.sign = 1u;

    (void)axis_map;
    (void)ctrl;
}

void imu_exti_irq_handler(void)
{
    s_sample_seq++;
}

/*
 * EXTI0 中断：读取 SPI 数据寄存器并发布最新样本。
 */
void EXTI0_IRQHandler(void)
{
    uint32_t raw = SPI1->DR;

    g_imu_raw = raw;
    g_imu_events++;
    imu_exti_irq_handler();

    /* 清中断标志 */
    *(volatile uint32_t *)0x40013C14u = 0x00000001u;
}
