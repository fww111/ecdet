#include "app.h"
#include <string.h>

bool ds_load_sequence(Mission *m, const SequenceStep *steps, size_t count)
{
    if (!steps || count > 12u) {
        return false;
    }
    memcpy(m->steps, steps, count * sizeof(*steps));
    m->step_count = count;
    for (size_t i = 0; i < count; ++i) {
        m->steps[i].executed = false;
    }
    return true;
}

bool ds_instrument_enable(Mission *m)
{
    m->instrument_on = true;
    return true;
}

void ds_sequence_step(App *app)
{
    Mission *m = &app->mission;
    for (size_t i = 0; i < m->step_count; ++i) {
        SequenceStep *step = &m->steps[i];
        uint32_t elapsed = app->platform.tick_ms - step->due;
        if (step->executed || elapsed >= 0x80000000u) {
            continue;
        }
        bool ok = true;
        switch (step->opcode) {
        case 1:
            ok = ds_instrument_enable(m);
            break;
        case 2:
            m->instrument_on = false;
            break;
        case 3:
            if (step->argument < 1u || step->argument > 100u) {
                ok = false;
            } else {
                m->instrument_gain = step->argument;
            }
            break;
        default:
            ok = false;
            break;
        }
        step->executed = true;
        if (ok) {
            ++m->executed;
        } else {
            ++m->rejected;
        }
        event_add(&app->events, app->platform.tick_ms, 210, ok ? 1 : -1);
    }
}
