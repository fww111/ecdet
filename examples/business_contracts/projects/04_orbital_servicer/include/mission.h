#ifndef MISSION_H
#define MISSION_H
#include "services.h"
typedef enum { OS_HOLD, OS_APPROACH, OS_ALIGN, OS_CAPTURE, OS_SERVICE, OS_RETREAT, OS_SAFE } OsMode;
typedef struct {
    float joints[4];
    uint16_t duration_ms;
    uint16_t flags;
} Waypoint;
typedef struct {
    OsMode mode;
    float range;
    float closing_speed;
    float lateral_error;
    float joint_position[4];
    float joint_target[4];
    Waypoint trajectory[6];
    size_t trajectory_count;
    size_t trajectory_index;
    uint32_t segment_start;
    uint32_t nav_timestamp;
    uint32_t captures;
    uint32_t rejected;
    uint32_t service_ticks;
    bool target_valid;
    bool latch_closed;
    bool drive_enabled;
    bool permit;
} Mission;
struct App;
void mission_init(struct App *app);
void mission_fast(struct App *app);
void mission_slow(struct App *app);
bool mission_command(struct App *app, const Command *command);
const char *mission_mode(const struct App *app);
unsigned mission_mode_id(const struct App *app);
bool os_set_joint(Mission *m, int index, float target);
bool os_load_path(Mission *m, const Waypoint *path, size_t count);
bool os_capture(Mission *m);
bool os_navigation_valid(const Mission *m, uint32_t now);
void os_arm_step(struct App *app);
void os_relative_step(struct App *app);
bool mission_nominal_check(const struct App *app);
void mission_report(const struct App *app);
void mission_shutdown(struct App *app);
#endif
