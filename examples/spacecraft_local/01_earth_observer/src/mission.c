#include <stdio.h>
#include "app.h"
#include <math.h>
#include <string.h>

static void transition(App *app, EoMode mode)
{
    app->mission.mode = mode;
    app->mission.mode_since = app->platform.tick_ms;
    event_add(&app->events, app->platform.tick_ms, 100, (int32_t)mode);
}

void mission_init(App *app)
{
    Mission *m = &app->mission;
    memset(m, 0, sizeof(*m));
    m->mode = EO_BOOT;
    m->exposure_ms = 30;
    m->rate[0] = 0.05f;
    m->rate[1] = -0.03f;
    m->rate[2] = 0.02f;
}

void mission_fast(App *app)
{
    eo_attitude_step(app);
    watchdog_kick(&app->watchdog, app->platform.tick_ms);
}

void mission_slow(App *app)
{
    Mission *m = &app->mission;
    uint32_t age = app->platform.tick_ms - m->mode_since;
    if (app->power.charge < 20.0f) {
        transition(app, EO_SAFE);
    }
    if (!app->platform.eclipse) {
        memcpy(m->star_angle, m->angle, sizeof(m->angle));
        m->star_timestamp = app->platform.tick_ms;
        m->star_valid = true;
    }
    switch (m->mode) {
    case EO_BOOT:
        transition(app, EO_DETUMBLE);
        break;
    case EO_DETUMBLE:
        if (fabsf(m->rate[0]) + fabsf(m->rate[1]) + fabsf(m->rate[2]) < 0.06f) {
            transition(app, EO_POINT);
        }
        break;
    case EO_POINT:
        if (age >= 1000u && !app->platform.eclipse) {
            transition(app, EO_IMAGE);
        }
        break;
    case EO_IMAGE:
        eo_camera_step(app);
        transition(app, EO_DOWNLINK);
        break;
    case EO_DOWNLINK:
        if (m->image_ready && app->platform.radio_visible &&
            platform_tx(&app->platform, m->tile, m->tile_size) == IO_OK) {
            ++m->downlinked;
            m->image_ready = false;
            transition(app, EO_POINT);
        }
        break;
    case EO_SAFE:
        if (app->power.charge > 40.0f) {
            transition(app, EO_DETUMBLE);
        }
        break;
    }
}

bool mission_command(App *app, const Command *command)
{
    Mission *m = &app->mission;
    switch (command->opcode) {
    case 100:
        if (command->length != 3u) {
            return false;
        }
        return eo_set_wheel(m, command->payload[0],
                            (float)(int16_t)read_be16(command->payload + 1) / 1000.0f);
    case 101:
        return eo_load_tile(m, command->payload, command->length);
    case 102:
        m->pixel_count = command->length / 2u;
        if (m->pixel_count > ARRAY_COUNT(m->pixels)) {
            return false;
        }
        for (size_t i = 0; i < m->pixel_count; ++i) {
            m->pixels[i] = read_be16(command->payload + i * 2u);
        }
        m->exposure_ms = eo_mean(m->pixels, m->pixel_count);
        return true;
    case 103:
        transition(app, EO_SAFE);
        return true;
    default:
        ++m->rejected;
        return false;
    }
}

const char *mission_mode(const App *app)
{
    static const char *names[] = {"boot", "detumble", "point", "image", "downlink", "safe"};
    unsigned index = (unsigned)app->mission.mode;
    return index < ARRAY_COUNT(names) ? names[index] : "invalid";
}

unsigned mission_mode_id(const App *app)
{
    return (unsigned)app->mission.mode;
}


bool mission_nominal_check(const App *app)
{
    const Mission *m = &app->mission;
    return m->images > 0 && m->downlinked > 0 && m->tile_size <= sizeof(m->tile);
}

void mission_report(const App *app)
{
    const Mission *m = &app->mission;
    printf("images=%lu downlinked=%lu\n", (unsigned long)m->images, (unsigned long)m->downlinked);
}

void mission_shutdown(App *app)
{
    (void)app;
}
