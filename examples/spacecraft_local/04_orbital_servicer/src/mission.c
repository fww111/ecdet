#include <stdio.h>
#include "app.h"
#include <string.h>

void mission_init(App *app)
{
    Mission *m = &app->mission;
    memset(m, 0, sizeof(*m));
    m->mode = OS_APPROACH;
    m->range = 1.2f;
    m->lateral_error = 0.1f;
    m->target_valid = true;
    m->drive_enabled = true;
    m->permit = true;
    Waypoint path[2] = {
        {{5.0f, -3.0f, 2.0f, 0.0f}, 1500, 0},
        {{0.0f, 0.0f, 0.0f, 0.0f}, 1500, 0}
    };
    (void)os_load_path(m, path, ARRAY_COUNT(path));
}

void mission_fast(App *app)
{
    os_relative_step(app);
    os_arm_step(app);
    watchdog_kick(&app->watchdog, app->platform.tick_ms);
}

void mission_slow(App *app)
{
    Mission *m = &app->mission;
    uint16_t value = 0;
    if (platform_read(&app->platform, 5, &value) == IO_OK) {
        m->target_valid = true;
        m->nav_timestamp = app->platform.tick_ms;
    }
    if (app->power.charge < 20.0f) {
        m->mode = OS_SAFE;
        m->drive_enabled = false;
    }
    switch (m->mode) {
    case OS_CAPTURE:
        (void)os_capture(m);
        break;
    case OS_SERVICE:
        ++m->service_ticks;
        if (m->service_ticks >= 6u) {
            m->latch_closed = false;
            m->mode = OS_RETREAT;
        }
        break;
    case OS_SAFE:
        m->closing_speed = 0.0f;
        break;
    default:
        break;
    }
    event_add(&app->events, app->platform.tick_ms, 410, (int32_t)m->mode);
}

bool mission_command(App *app, const Command *command)
{
    Mission *m = &app->mission;
    switch (command->opcode) {
    case 400:
        if (command->length != 3u) {
            return false;
        }
        return os_set_joint(m, (int8_t)command->payload[0],
                            (float)(int16_t)read_be16(command->payload + 1) / 100.0f);
    case 401:
        return os_capture(m);
    case 402:
        m->mode = OS_RETREAT;
        m->latch_closed = false;
        return true;
    case 403: {
        if (command->length % 6u != 0) {
            return false;
        }
        Waypoint path[10] = {0};
        size_t count = command->length / 6u;
        for (size_t i = 0; i < count; ++i) {
            for (unsigned j = 0; j < 4u; ++j) {
                path[i].joints[j] = (float)(int8_t)command->payload[i * 6u + j];
            }
            path[i].duration_ms = read_be16(command->payload + i * 6u + 4u);
        }
        m->segment_start = app->platform.tick_ms;
        return os_load_path(m, path, count);
    }
    default:
        ++m->rejected;
        return false;
    }
}

const char *mission_mode(const App *app)
{
    static const char *names[] = {"hold", "approach", "align", "capture", "service", "retreat", "safe"};
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
    return m->captures > 0 && m->service_ticks >= 6u && m->trajectory_index == m->trajectory_count;
}

void mission_report(const App *app)
{
    const Mission *m = &app->mission;
    printf("captures=%lu service_ticks=%lu waypoints=%lu\n", (unsigned long)m->captures, (unsigned long)m->service_ticks, (unsigned long)m->trajectory_index);
}

void mission_shutdown(App *app)
{
    (void)app;
}
