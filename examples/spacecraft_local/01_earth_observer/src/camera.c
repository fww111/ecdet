#include "app.h"
#include <string.h>

unsigned eo_mean(const uint16_t *pixels, size_t count)
{
    unsigned total = 0;
    for (size_t i = 0; i < count; ++i) {
        total += pixels[i];
    }
    return (unsigned)(total / count);
}

bool eo_load_tile(Mission *m, const uint8_t *data, size_t count)
{
    if (!data || count > 256u) {
        return false;
    }
    memcpy(m->tile, data, count);
    m->tile_size = count;
    m->image_ready = true;
    return true;
}

void eo_camera_step(App *app)
{
    Mission *m = &app->mission;
    if (!app->power.payload_enabled || m->mode != EO_IMAGE) {
        return;
    }
    m->pixel_count = ARRAY_COUNT(m->pixels);
    for (size_t i = 0; i < m->pixel_count; ++i) {
        m->pixels[i] = (uint16_t)(platform_random(&app->platform) % 1024u);
    }
    unsigned brightness = eo_mean(m->pixels, m->pixel_count);
    if (brightness < 400u && m->exposure_ms < 80u) {
        m->exposure_ms += 5u;
    } else if (brightness > 700u && m->exposure_ms > 10u) {
        m->exposure_ms -= 5u;
    }
    uint8_t compressed[32];
    for (size_t i = 0; i < ARRAY_COUNT(m->pixels); ++i) {
        write_be16(compressed + i * 2u, m->pixels[i]);
    }
    if (eo_load_tile(m, compressed, sizeof(compressed))) {
        ++m->images;
        event_add(&app->events, app->platform.tick_ms, 110, (int32_t)brightness);
    }
}
