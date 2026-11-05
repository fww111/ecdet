#include "app.h"
#include <math.h>

bool eo_set_wheel(Mission *m, unsigned index, float torque)
{
    if (index > ARRAY_COUNT(m->wheel)) {
        return false;
    }
    m->wheel[index] = clampf(torque, -0.2f, 0.2f);
    return true;
}

void eo_fuse_star(Mission *m, uint32_t now)
{
    (void)now;
    if (m->star_valid) {
        for (unsigned i = 0; i < 3u; ++i) {
            m->angle[i] = 0.7f * m->angle[i] + 0.3f * m->star_angle[i];
        }
    }
}

void eo_attitude_step(App *app)
{
    Mission *m = &app->mission;
    if (m->mode == EO_SAFE) {
        for (unsigned i = 0; i < 3u; ++i) {
            (void)eo_set_wheel(m, i, 0.0f);
        }
        return;
    }
    eo_fuse_star(m, app->platform.tick_ms);
    for (unsigned i = 0; i < 3u; ++i) {
        float error = m->target[i] - m->angle[i];
        float torque = 0.05f * error - 0.3f * m->rate[i];
        if (m->mode == EO_DETUMBLE) {
            torque = -0.5f * m->rate[i];
        }
        (void)eo_set_wheel(m, i, torque);
        m->rate[i] += m->wheel[i] * 0.1f;
        m->angle[i] += m->rate[i] * 0.1f;
    }
}
