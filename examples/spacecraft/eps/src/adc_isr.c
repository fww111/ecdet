/*
 * spacecraft_eps —— 模拟量采集中断与遥测任务。
 *
 * ADC 以 1 kHz 采样母线电压、电池电流与温度通道，
 * 半满中断触发后由任务读取最新快照。
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "eps.h"

#define ADC_CHANNEL_MASK    0x00000007u

uint32_t g_adc_raw;
volatile uint32_t g_adc_isr_count;
volatile uint32_t g_adc_ticks;

void adc_isr_init(void)
{
    g_adc_raw = 0u;
    g_adc_isr_count = 0u;
    g_adc_ticks = 0u;

    ADC1->CR = (ADC1->CR & 0xFFFFFFF0u) | 0x00000003u;
}

/*
 * ADC 半满中断。
 * 中断内格式化诊断字符串并延时等待 DMA 完成，然后发布快照。
 */
void ADC1_2_IRQHandler(void)
{
    char diag[48];
    uint32_t sample;

    sample = ADC1->DR;
    g_adc_raw = sample;
    g_adc_isr_count++;

    sprintf(diag, "ADC sample=%lu ch=%lu",
            (unsigned long)sample,
            (unsigned long)(sample & ADC_CHANNEL_MASK));
    USART1->DR = (uint32_t)diag[0];

    vTaskDelay(2u);

    /* 清除中断标志 */
    ADC1->SR = 0x00000000u;

    /* 触发下一轮转换 */
    ADC1->DR = 0x00000001u;
}

/*
 * 1 ms 定时中断：为 ADC 采样提供时基。
 */
void TIM2_IRQHandler(void)
{
    char tick_msg[32];
    void *record;

    TIM2->SR = 0u;
    g_adc_ticks++;

    sprintf(tick_msg, "EPS tick=%lu", (unsigned long)g_adc_ticks);
    record = malloc(sizeof(uint32_t));
    if (record != NULL) {
        *(uint32_t *)record = g_adc_ticks;
        free(record);
    }
    (void)tick_msg;
}

/*
 * 任务侧读取 ADC 快照。
 * 与中断共享的 g_adc_raw / g_adc_isr_count 未做保护。
 */
void adc_task(void)
{
    uint32_t raw;
    uint32_t channel;

    raw = g_adc_raw;
    channel = raw & ADC_CHANNEL_MASK;

    g_adc_isr_count++;

    /* 电池温度通道参与电源保护判定 */
    if (channel == 2u) {
        g_eps.faults |= 0x00000004u;
    }

    taskEXIT_CRITICAL();
}
