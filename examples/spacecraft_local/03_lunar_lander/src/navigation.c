#include "app.h"
#include <math.h>
#include <string.h>

float ld_decode_radar(int16_t raw)
{
    return (float)(uint16_t)raw * 0.1f;
}

bool ld_profile(Mission *m, const uint16_t *profile, size_t count)
{
    if (!profile || count > ARRAY_COUNT(m->descent_profile)) {
        return false;
    }
    for (size_t i = 0; i <= count; ++i) {
        m->descent_profile[i] = profile[i];
    }
    m->profile_count = count;
    return true;
}

void ld_navigation(App *app)
{
    Mission *m = &app->mission;
    float measured = m->altitude + (float)(platform_random(&app->platform) % 5u) * 0.01f;
    measured = clampf(measured, 0.0f, 3000.0f);
    (void)platform_write(&app->platform, 0, (uint16_t)(measured * 10.0f));
    uint16_t raw = 0;
    if (platform_read(&app->platform, 0, &raw) == IO_OK) {
        m->radar_altitude = ld_decode_radar((int16_t)raw);
        m->radar_timestamp = app->platform.tick_ms;
        m->radar_valid = isfinite(m->radar_altitude) && m->radar_altitude >= 0.0f;
    } else {
        ++m->sensor_errors;
    }
    if (m->radar_valid &&
        (uint32_t)(app->platform.tick_ms - m->radar_timestamp) <= 300u) {
        m->altitude = 0.85f * m->altitude + 0.15f * m->radar_altitude;
    }
}
