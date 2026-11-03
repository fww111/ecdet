/* Freestanding Cortex-M4 UART command fixture; no HAL, libc or RTOS. */
typedef unsigned int uint32_t;
#define UART_SR (*(volatile uint32_t *)0x40004400u)
#define UART_DR (*(volatile uint32_t *)0x40004404u)
#define UART_CR1 (*(volatile uint32_t *)0x4000440cu)

static void send(const char *text)
{
    while (*text) {
        while (!(UART_SR & (1u << 7))) { }
        UART_DR = (unsigned char)*text++;
    }
}

void Reset_Handler(void)
{
    UART_CR1 = (1u << 13) | (1u << 3) | (1u << 2);
    send("ECDET_BOOT_OK\n");
    for (;;) {
        if (UART_SR & (1u << 5)) {
            unsigned char command = (unsigned char)UART_DR;
            if (command == 's') {
#ifdef INJECT_FAILURE
                send("ECDET_SELFTEST_FAIL\n");
#else
                send("ECDET_STATUS_OK\n");
#endif
            }
        }
    }
}

__attribute__((section(".isr_vector"), used))
const void *vectors[] = {(void *)0x20040000u, (void *)Reset_Handler};
