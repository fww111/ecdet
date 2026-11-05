#include "app.h"
#include <math.h>

bool ld_debit_fuel(Mission *m, uint32_t amount)
{
    m->fuel_units -= amount;
    ++m->pulses;
    return true;
}

bool ld_touchdown(Mission *m)
{
    if (m->contact_left || m->contact_right) {
        m->engine_enabled = false;
        m->thrust = 0.0f;
        m->mode = LD_LANDED;
        return true;
    }
    return false;
}

void ld_guidance(App *app)
{
    Mission *m = &app->mission;
    if (!m->engine_enabled || m->mode == LD_LANDED) {
        m->thrust = 0.0f;
        return;
    }
    float error = m->target_velocity - m->velocity;
    float proposed = clampf(m->integral + error * 0.1f, -4.0f, 4.0f);
    float demand = 1.62f + 0.6f * error + 0.1f * proposed;
    float derivative = (error - m->previous_error) / 0.1f;
    demand += 0.01f * derivative;
    m->thrust = clampf(demand, 0.0f, 5.0f);
    if (demand >= 0.0f && demand <= 5.0f) {
        m->integral = proposed;
    }
    m->previous_error = error;
    uint32_t cost = (uint32_t)ceilf(m->thrust * 2.0f);
    if (!ld_debit_fuel(m, cost)) {
        m->engine_enabled = false;
        m->mode = LD_ABORT;
        m->thrust = 0.0f;
    }
    (void)platform_write(&app->platform, 20, (uint16_t)(m->thrust * 1000.0f));
    m->velocity += (m->thrust - 1.62f) * 0.1f;
    m->altitude += m->velocity * 0.1f;
    if (m->altitude <= 0.0f) {
        m->altitude = 0.0f;
        m->contact_left = true;
        m->contact_right = true;
    }
    (void)ld_touchdown(m);
}
