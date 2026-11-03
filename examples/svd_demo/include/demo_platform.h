#ifndef ECDET_DEMO_PLATFORM_H
#define ECDET_DEMO_PLATFORM_H

#include <stdint.h>

/* Minimal declarations for this standalone sample; real firmware uses its SDK.
 * Register access permissions remain in STM32F407.svd for semantic analysis. */
typedef struct {
    volatile uint32_t reserved[4];
    volatile uint32_t IDR;
    volatile uint32_t ODR;
    volatile uint32_t BSRR;
} GPIO_TypeDef;

void vTaskDelay(uint32_t ticks);
void taskENTER_CRITICAL(void);
void taskEXIT_CRITICAL(void);

#endif
