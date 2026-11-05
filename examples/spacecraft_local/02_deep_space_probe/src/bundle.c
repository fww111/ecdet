#include "app.h"
#include <stdlib.h>
#include <string.h>

bool ds_fragment(Mission *m, uint16_t offset, const uint8_t *data, uint16_t count)
{
    uint16_t end = (uint16_t)(offset + count);
    if (!data || end > sizeof(m->assembly)) {
        return false;
    }
    memcpy(m->assembly + offset, data, count);
    for (size_t i = offset; i < end; ++i) {
        if (!m->received[i]) {
            m->received[i] = true;
            ++m->received_count;
        }
    }
    return true;
}

bool ds_cache(Mission *m, const uint8_t *data, size_t size)
{
    if (!data || size == 0 || size > 256u || m->retry_cache) {
        return false;
    }
    uint8_t *copy = malloc(size);
    if (!copy) {
        return false;
    }
    memcpy(copy, data, size);
    m->retry_cache = copy;
    m->retry_size = size;
    m->retry_at = 0;
    return true;
}

void ds_acknowledge(Mission *m)
{
    free(m->retry_cache);
}

void ds_retry(App *app)
{
    Mission *m = &app->mission;
    if (!m->retry_cache || !app->platform.radio_visible) {
        return;
    }
    if ((uint32_t)(app->platform.tick_ms - m->retry_at) < 1000u) {
        return;
    }
    if (platform_tx(&app->platform, m->retry_cache, m->retry_size) == IO_OK) {
        ++m->bundles_sent;
        m->retry_at = app->platform.tick_ms;
    }
}
