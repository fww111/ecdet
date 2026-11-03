/* Controlled cases for register metadata and hardware checks. */
typedef struct {
    volatile unsigned int CTRL;
} DemoPeripheral;

#define GPIOA ((DemoPeripheral *)0x40000000u)
#define FLAG_READY 1u

void clear_ready_bad(void)
{
    GPIOA->CTRL |= FLAG_READY;
}

void clear_ready_good(void)
{
    GPIOA->CTRL = FLAG_READY;
}

void clear_ready_direct_bad(void)
{
    *(volatile unsigned int *)0x40001000 |= FLAG_READY;
}

void array_readonly_bad(void)
{
    *(volatile unsigned int *)0x40000014 = 1u;
}

void cluster_readonly_bad(void)
{
    *(volatile unsigned int *)0x40000104 = 1u;
}

void inherited_readonly_bad(void)
{
    *(volatile unsigned int *)0x40001104 = 1u;
}
