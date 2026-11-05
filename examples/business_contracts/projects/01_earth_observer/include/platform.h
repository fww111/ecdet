#ifndef PLATFORM_H
#define PLATFORM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define ARRAY_COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define FLASH_SIZE 8192u
#define FLASH_PAGE 128u
typedef enum {
    IO_OK = 0,
    IO_RANGE = -1,
    IO_TIMEOUT = -2,
    IO_BUSY = -3,
    IO_INVALID = -4
} IoStatus;
typedef struct {
    uint32_t tick_ms;
    uint32_t random_state;
    uint32_t bus_reads;
    uint32_t bus_writes;
    uint32_t fail_every;
    bool eclipse;
    bool radio_visible;
    uint8_t flash[FLASH_SIZE];
    uint16_t registers[32];
    uint8_t tx[256];
    size_t tx_size;
} Platform;
void platform_init(Platform *p, uint32_t seed);
void platform_advance(Platform *p, uint32_t delta);
uint32_t platform_random(Platform *p);
IoStatus platform_read(Platform *p, unsigned channel, uint16_t *value);
IoStatus platform_write(Platform *p, unsigned channel, uint16_t value);
IoStatus platform_tx(Platform *p, const uint8_t *data, size_t size);
IoStatus platform_erase(Platform *p, size_t page);
IoStatus platform_program(Platform *p, size_t address,
                          const uint8_t *data, size_t size);
uint16_t read_be16(const uint8_t *data);
void write_be16(uint8_t *data, uint16_t value);
uint16_t crc16(const uint8_t *data, size_t size);
float clampf(float value, float low, float high);
#endif
