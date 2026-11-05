#include "services.h"

void power_init(Power *power)
{
    power->voltage = 28.0f;
    power->charge = 85.0f;
    power->temperature = 15.0f;
    power->load_watts = 12.0f;
    power->payload_enabled = true;
    power->heater_enabled = false;
    power->shed_count = 0;
}

bool power_request(Power *power, float watts)
{
    if (watts < 0.0f || watts > 60.0f || power->charge < 20.0f) {
        return false;
    }
    power->load_watts = watts;
    return true;
}

void power_update(Power *power, Platform *p, float dt)
{
    float generated = p->eclipse ? 0.0f : 35.0f;
    float load = power->load_watts + (power->heater_enabled ? 8.0f : 0.0f);
    power->charge = clampf(power->charge + (generated - load) * dt / 300.0f,
                           0.0f, 100.0f);
    power->voltage = 22.0f + power->charge * 0.07f;
    float equilibrium = p->eclipse ? -15.0f : 25.0f;
    power->temperature += (equilibrium - power->temperature) * dt * 0.02f;
    if (power->heater_enabled) {
        power->temperature += dt * 0.3f;
    }
    if (power->temperature < 0.0f) {
        power->heater_enabled = true;
    } else if (power->temperature > 5.0f) {
        power->heater_enabled = false;
    }
    if (power->charge < 20.0f && power->payload_enabled) {
        power->payload_enabled = false;
        power->load_watts = 8.0f;
        ++power->shed_count;
    } else if (power->charge > 35.0f) {
        power->payload_enabled = true;
    }
}
