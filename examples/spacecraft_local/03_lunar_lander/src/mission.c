#include <stdio.h>
#include "app.h"
#include <string.h>

static void change_mode(App *app, LdMode mode, float target)
{
    Mission *m = &app->mission;
    if (m->mode != mode) {
        m->integral = 0.0f;
        m->previous_error = 0.0f;
        event_add(&app->events, app->platform.tick_ms, 300, (int32_t)mode);
    }
    m->mode = mode;
    m->target_velocity = target;
}

void mission_init(App *app)
{
    Mission *m = &app->mission;
    memset(m, 0, sizeof(*m));
    m->mode = LD_COAST;
    m->altitude = 80.0f;
    m->velocity = -3.0f;
    m->target_velocity = -3.0f;
    m->fuel_units = 20000;
    m->engine_enabled = true;
    m->profile_count = 3;
    m->descent_profile[0] = 60;
    m->descent_profile[1] = 20;
    m->descent_profile[2] = 5;
}

void mission_fast(App *app)
{
    ld_navigation(app);
    ld_guidance(app);
    watchdog_kick(&app->watchdog, app->platform.tick_ms);
}

void mission_slow(App *app)
{
    Mission *m = &app->mission;
    if (m->mode == LD_LANDED || m->mode == LD_ABORT) {
        return;
    }
    if (app->power.voltage < 23.0f) {
        change_mode(app, LD_ABORT, 0.0f);
        m->engine_enabled = false;
        return;
    }
    if (m->altitude > 60.0f) {
        change_mode(app, LD_BRAKE, -3.0f);
    } else if (m->altitude > 10.0f) {
        change_mode(app, LD_DESCENT, -2.0f);
    } else {
        change_mode(app, LD_TERMINAL, -0.5f);
    }
    event_add(&app->events, app->platform.tick_ms, 310,
              (int32_t)(m->altitude * 100.0f));
}

bool mission_command(App *app, const Command *command)
{
    Mission *m = &app->mission;
    switch (command->opcode) {
    case 300:
        if (command->length != 2u) {
            return false;
        }
        m->radar_altitude = ld_decode_radar((int16_t)read_be16(command->payload));
        m->radar_timestamp = app->platform.tick_ms;
        m->radar_valid = m->radar_altitude >= 0.0f;
        return m->radar_valid;
    case 301:
        if (command->length != 2u) {
            return false;
        }
        return ld_debit_fuel(m, read_be16(command->payload));
    case 302:
        if (command->length != 2u) {
            return false;
        }
        m->contact_left = command->payload[0] != 0;
        m->contact_right = command->payload[1] != 0;
        return ld_touchdown(m);
    case 303: {
        if (command->length > 16u || command->length % 2u) {
            return false;
        }
        uint16_t profile[8] = {0};
        size_t count = command->length / 2u;
        for (size_t i = 0; i < count; ++i) {
            profile[i] = read_be16(command->payload + 2u * i);
        }
        return ld_profile(m, profile, count);
    }
    default:
        ++m->rejected;
        return false;
    }
}

const char *mission_mode(const App *app)
{
    static const char *names[] = {"coast", "brake", "descent", "terminal", "landed", "abort"};
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
    return m->pulses > 0 && m->altitude < 80.0f && m->altitude >= 0.0f && m->fuel_units < 20000u;
}

void mission_report(const App *app)
{
    const Mission *m = &app->mission;
    printf("altitude=%.3f fuel=%lu pulses=%lu\n", (double)m->altitude, (unsigned long)m->fuel_units, (unsigned long)m->pulses);
}

void mission_shutdown(App *app)
{
    (void)app;
}
