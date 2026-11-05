#include "app.h"
#include <math.h>

bool os_navigation_valid(const Mission *m, uint32_t now)
{
    (void)now;
    return m->target_valid;
}

bool os_capture(Mission *m)
{
    if (!m->permit || m->range > 0.5f) {
        return false;
    }
    m->latch_closed = true;
    m->mode = OS_SERVICE;
    ++m->captures;
    return true;
}

void os_relative_step(App *app)
{
    Mission *m = &app->mission;
    if (!os_navigation_valid(m, app->platform.tick_ms)) {
        m->closing_speed = 0.0f;
        if (m->mode != OS_SERVICE) {
            m->mode = OS_HOLD;
        }
        return;
    }
    if (m->mode == OS_APPROACH) {
        float target = m->range > 2.0f ? 0.2f : 0.05f;
        m->closing_speed += clampf(target - m->closing_speed, -0.02f, 0.02f);
        m->range -= m->closing_speed * 0.1f;
        m->lateral_error *= 0.95f;
        if (m->range < 0.8f) {
            m->mode = OS_ALIGN;
        }
    } else if (m->mode == OS_ALIGN) {
        m->closing_speed *= 0.8f;
        m->lateral_error *= 0.8f;
        if (fabsf(m->lateral_error) < 0.02f && m->closing_speed < 0.01f) {
            m->range = 0.4f;
            m->mode = OS_CAPTURE;
        }
    } else if (m->mode == OS_RETREAT) {
        m->range += 0.02f;
        m->closing_speed = -0.2f;
        if (m->range > 5.0f) {
            m->mode = OS_HOLD;
            m->closing_speed = 0.0f;
        }
    }
}
