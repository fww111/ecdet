#include <stdlib.h>
#include <stdio.h>
#include "app.h"
#include <string.h>

void mission_init(App *app)
{
    Mission *m = &app->mission;
    memset(m, 0, sizeof(*m));
    m->mode = DS_CRUISE;
    m->instrument_gain = 4;
    SequenceStep initial[] = {
        {500, 1, 0, false},
        {3000, 3, 8, false},
        {8000, 2, 0, false}
    };
    (void)ds_load_sequence(m, initial, ARRAY_COUNT(initial));
}

void mission_fast(App *app)
{
    ds_sequence_step(app);
    ds_retry(app);
    watchdog_kick(&app->watchdog, app->platform.tick_ms);
}

void mission_slow(App *app)
{
    Mission *m = &app->mission;
    if (app->power.charge < 20.0f || m->mode == DS_SAFE) {
        m->mode = DS_SAFE;
        m->instrument_on = false;
    } else if (app->platform.radio_visible) {
        m->mode = DS_CONTACT;
    } else if (m->instrument_on) {
        m->mode = DS_SCIENCE;
    } else {
        m->mode = DS_CRUISE;
    }
    if (!m->instrument_on || !app->power.payload_enabled) {
        return;
    }
    uint8_t spectrum[32];
    for (size_t i = 0; i < ARRAY_COUNT(m->bins); ++i) {
        uint16_t raw = 0;
        if (platform_read(&app->platform, (unsigned)i, &raw) != IO_OK) {
            event_add(&app->events, app->platform.tick_ms, 220, (int32_t)i);
            return;
        }
        m->bins[i] = (uint16_t)((raw / 16u) * m->instrument_gain);
        write_be16(spectrum + i * 2u, m->bins[i]);
    }
    ++m->spectra;
    (void)ds_fragment(m, 0, spectrum, sizeof(spectrum));
    if (!m->retry_cache) {
        (void)ds_cache(m, spectrum, sizeof(spectrum));
    }
    event_add(&app->events, app->platform.tick_ms, 221, (int32_t)m->spectra);
}

bool mission_command(App *app, const Command *command)
{
    Mission *m = &app->mission;
    switch (command->opcode) {
    case 200:
        if (command->length < 2u) {
            return false;
        }
        return ds_fragment(m, read_be16(command->payload), command->payload + 2,
                           (uint16_t)(command->length - 2u));
    case 201:
        ds_acknowledge(m);
        return true;
    case 202:
        return ds_instrument_enable(m);
    case 203:
        m->mode = DS_SAFE;
        m->instrument_on = false;
        return true;
    case 204: {
        if (command->length % 4u != 0) {
            return false;
        }
        SequenceStep steps[16] = {0};
        size_t count = command->length / 4u;
        for (size_t i = 0; i < count; ++i) {
            const uint8_t *p = command->payload + 4u * i;
            steps[i].due = app->platform.tick_ms + read_be16(p);
            steps[i].opcode = p[2];
            steps[i].argument = p[3];
        }
        return ds_load_sequence(m, steps, count);
    }
    default:
        ++m->rejected;
        return false;
    }
}

const char *mission_mode(const App *app)
{
    static const char *names[] = {"cruise", "science", "contact", "safe"};
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
    return m->spectra > 0 && m->bundles_sent > 0 && m->executed == 3u && !m->instrument_on;
}

void mission_report(const App *app)
{
    const Mission *m = &app->mission;
    printf("spectra=%lu bundles=%lu executed=%lu\n", (unsigned long)m->spectra, (unsigned long)m->bundles_sent, (unsigned long)m->executed);
}

void mission_shutdown(App *app)
{
    free(app->mission.retry_cache);
    app->mission.retry_cache = NULL;
}
