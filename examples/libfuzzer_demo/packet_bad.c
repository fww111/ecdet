#include <stddef.h>
#include <stdint.h>

static volatile uint8_t observation;

int parse_packet(const uint8_t *data, size_t size)
{
    uint8_t payload[4] = {0};
    if (size < 2) return 0;
    if (data[0] == 0xa5) {
        unsigned index = data[1];
        payload[index] = data[0];
        observation = payload[0];
    }
    return 0;
}
