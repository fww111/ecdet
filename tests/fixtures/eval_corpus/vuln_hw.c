/* 评测语料：硬件语义类漏洞样例（P2 消融验证） */
#include <stdint.h>

#define GPIOA ((GPIO_TypeDef *) 0x40020000)

volatile uint32_t g_hw_rx;

/* 漏洞函数：ISR 调用阻塞 API */
void TIM6_IRQHandler(void)
{
    vTaskDelay(1);
}

/* 漏洞函数：写只读寄存器 */
void gpio_ro_write(void)
{
    GPIOA->IDR = 1u;
}

/* 漏洞函数：ISR 写共享变量 */
void UART8_IRQHandler(void)
{
    g_hw_rx = GPIOA->ODR;
}

/* 漏洞函数：无临界区保护读取 ISR 共享变量（竞争显现点） */
void unprotected_reader(void)
{
    g_hw_rx += 1u;
}

/* 干净函数：临界区保护访问 */
void protected_reader(void)
{
    uint32_t x;
    taskENTER_CRITICAL();
    x = g_hw_rx;
    taskEXIT_CRITICAL();
    (void)x;
}
