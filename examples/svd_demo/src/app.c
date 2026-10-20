/*
 * svd_demo —— 阶段二硬件语义检查演示。
 * 埋设缺陷：
 *   1. GPIOA->IDR = …      写只读寄存器（ECDET-MMIO-ACCESS error）
 *   2. x = GPIOA->BSRR     读只写寄存器（ECDET-MMIO-ACCESS warning）
 *   3. 直址 0x40020010 写  = 写 IDR（ECDET-MMIO-ACCESS error）
 *   4. g_ctrl ISR 写 / main 读，无临界区、无 volatile（RACE + VOLATILE）
 *   5. TIM2_IRQHandler 调 vTaskDelay（ECDET-ISR-BLOCK error）
 *   6. 常量传播证明下标越界（CERT C ARR30-C，Proven 级）
 * 干净参照：ODR 读写、临界区保护访问均不告警。
 */
#include <stdint.h>

/* 寄存器基址宏（真实的两级展开形态） */
#define PERIPH_BASE      0x40000000UL
#define GPIOA_BASE       (PERIPH_BASE + 0x00020000UL)
#define GPIOA            ((GPIO_TypeDef *) GPIOA_BASE)

/* 共享变量：g_rx 带 volatile 且有临界区保护（干净）；
   g_ctrl 两者皆无（缺陷）。 */
volatile uint32_t g_rx;
uint32_t g_ctrl;

/* 抽象解释（常量传播）演示缓冲区 */
static uint32_t s_ring[8];

void proven_overflow(void)
{
    int i = 99;
    s_ring[i] = 1u;             /* 折叠证明 99 >= 8：Proven 级越界 */
}

void USART1_IRQHandler(void)
{
    uint32_t data;

    data = GPIOA->ODR;          /* rw 读：合法 */
    g_rx = data;
    g_ctrl = 1u;                /* ISR 侧写入共享变量 */
}

void TIM2_IRQHandler(void)
{
    vTaskDelay(1);              /* 阻塞 API 进 ISR：ECDET-ISR-BLOCK */
}

void task_poll(void)
{
    uint32_t x = 0u;

    taskENTER_CRITICAL();       /* g_rx 有临界区保护：不告警 */
    x += g_rx;
    taskEXIT_CRITICAL();

    x += g_ctrl;                /* 无保护访问：ECDET-ISR-RACE */

    GPIOA->ODR = 1u;            /* rw 写：合法 */
    GPIOA->IDR = 1u;            /* 写只读寄存器：ECDET-MMIO-ACCESS */
    x |= GPIOA->BSRR;           /* 读只写寄存器：ECDET-MMIO-ACCESS */
    *(volatile uint32_t *)0x40020010 = 0u;   /* 直址写 IDR：ECDET-MMIO-ACCESS */
    (void)x;
}

int main(void)
{
    g_rx = 0u;
    g_ctrl = 0u;
    task_poll();
    return 0;
}
