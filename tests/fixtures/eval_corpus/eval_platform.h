#ifndef ECDET_EVAL_PLATFORM_H
#define ECDET_EVAL_PLATFORM_H

#include <stdint.h>

/* Standalone fixture declarations; register permissions come from chip.svd. */
typedef struct {
    volatile uint32_t reserved[4];
    volatile uint32_t IDR;
    volatile uint32_t ODR;
} GPIO_TypeDef;

void vTaskDelay(uint32_t ticks);
void taskENTER_CRITICAL(void);
void taskEXIT_CRITICAL(void);

#endif
