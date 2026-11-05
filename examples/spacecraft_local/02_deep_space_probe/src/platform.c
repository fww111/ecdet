#include "platform.h"
#include <string.h>

void platform_init(Platform *p, uint32_t seed)
{
    memset(p, 0, sizeof(*p));
    memset(p->flash, 0xff, sizeof(p->flash));
    p->random_state = seed ? seed : 1u;
    p->radio_visible = true;
    for (unsigned i = 0; i < ARRAY_COUNT(p->registers); ++i) {
        p->registers[i] = (uint16_t)(1000u + i * 20u);
    }
}

void platform_advance(Platform *p, uint32_t delta)
{
    p->tick_ms += delta;
    p->eclipse = (p->tick_ms / 3000u) % 2u != 0;
    p->radio_visible = (p->tick_ms / 2000u) % 3u != 2u;
}

uint32_t platform_random(Platform *p)
{
    uint32_t x = p->random_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    p->random_state = x;
    return x;
}

IoStatus platform_read(Platform *p, unsigned channel, uint16_t *value)
{
    if (!value || channel >= ARRAY_COUNT(p->registers)) {
        return IO_RANGE;
    }
    ++p->bus_reads;
    if (p->fail_every && p->bus_reads % p->fail_every == 0) {
        return IO_TIMEOUT;
    }
    *value = p->registers[channel];
    return IO_OK;
}

IoStatus platform_write(Platform *p, unsigned channel, uint16_t value)
{
    if (channel >= ARRAY_COUNT(p->registers)) {
        return IO_RANGE;
    }
    ++p->bus_writes;
    p->registers[channel] = value;
    return IO_OK;
}

IoStatus platform_tx(Platform *p, const uint8_t *data, size_t size)
{
    if (!data || size > sizeof(p->tx)) {
        return IO_RANGE;
    }
    if (!p->radio_visible) {
        return IO_BUSY;
    }
    memcpy(p->tx, data, size);
    p->tx_size = size;
    return IO_OK;
}

IoStatus platform_erase(Platform *p, size_t page)
{
    if (page >= FLASH_SIZE / FLASH_PAGE) {
        return IO_RANGE;
    }
    memset(p->flash + page * FLASH_PAGE, 0xff, FLASH_PAGE);
    return IO_OK;
}

IoStatus platform_program(Platform *p, size_t address,
                          const uint8_t *data, size_t size)
{
    if (!data || address > FLASH_SIZE || size > FLASH_SIZE - address) {
        return IO_RANGE;
    }
    for (size_t i = 0; i < size; ++i) {
        if ((p->flash[address + i] & data[i]) != data[i]) {
            return IO_INVALID;
        }
    }
    for (size_t i = 0; i < size; ++i) {
        p->flash[address + i] &= data[i];
    }
    return IO_OK;
}

uint16_t read_be16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

void write_be16(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)value;
}

uint16_t crc16(const uint8_t *data, size_t size)
{
    uint16_t crc = 0xffffu;
    for (size_t i = 0; i < size; ++i) {
        crc ^= (uint16_t)((uint16_t)data[i] << 8);
        for (unsigned bit = 0; bit < 8; ++bit) {
            crc = (uint16_t)((crc & 0x8000u) ?
                  ((uint32_t)crc << 1) ^ 0x1021u : (uint32_t)crc << 1);
        }
    }
    return crc;
}

float clampf(float value, float low, float high)
{
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}
