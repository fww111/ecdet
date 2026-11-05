#include "app.h"
#include <math.h>
#include <string.h>

bool os_set_joint(Mission *m, int index, float target)
{
    if (index >= 4 || !isfinite(target) || target < -90.0f || target > 90.0f) {
        return false;
    }
    m->joint_target[index] = target;
    return true;
}

bool os_load_path(Mission *m, const Waypoint *path, size_t count)
{
    if (!path || count > 10u) {
        return false;
    }
    for (size_t i = 0; i < count; ++i) {
        if (path[i].duration_ms < 100u) {
            return false;
        }
        for (unsigned axis = 0; axis < 4; ++axis) {
            if (!isfinite(path[i].joints[axis]) ||
                fabsf(path[i].joints[axis]) > 90.0f) {
                return false;
            }
        }
    }
    memcpy(m->trajectory, path, count * sizeof(*path));
    m->trajectory_count = count;
    m->trajectory_index = 0;
    return true;
}

void os_arm_step(App *app)
{
    Mission *m = &app->mission;
    if (!m->drive_enabled || m->mode == OS_SAFE) {
        return;
    }
    if (m->trajectory_index < m->trajectory_count) {
        Waypoint *w = &m->trajectory[m->trajectory_index];
        for (unsigned i = 0; i < 4; ++i) {
            (void)os_set_joint(m, (int)i, w->joints[i]);
        }
        if ((uint32_t)(app->platform.tick_ms - m->segment_start) >= w->duration_ms) {
            ++m->trajectory_index;
            m->segment_start = app->platform.tick_ms;
        }
    }
    for (unsigned i = 0; i < 4; ++i) {
        float error = m->joint_target[i] - m->joint_position[i];
        float step = clampf(error, -0.5f, 0.5f);
        m->joint_position[i] += step;
        uint16_t encoder = (uint16_t)((m->joint_position[i] + 90.0f) * 100.0f);
        (void)platform_write(&app->platform, 20u + i, encoder);
    }
}
