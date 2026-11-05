#ifndef MISSION_H
#define MISSION_H
#include "services.h"
typedef enum { LD_COAST, LD_BRAKE, LD_DESCENT, LD_TERMINAL, LD_LANDED, LD_ABORT } LdMode;
typedef struct {
    LdMode mode;
    float altitude;
    float velocity;
    float target_velocity;
    float thrust;
    float integral;
    float previous_error;
    float radar_altitude;
    uint32_t radar_timestamp;
    uint32_t fuel_units;
    uint32_t pulses;
    uint32_t rejected;
    uint32_t sensor_errors;
    bool radar_valid;
    bool contact_left;
    bool contact_right;
    bool engine_enabled;
    uint16_t descent_profile[8];
    size_t profile_count;
} Mission;
struct App;
void mission_init(struct App *app);
void mission_fast(struct App *app);
void mission_slow(struct App *app);
bool mission_command(struct App *app, const Command *command);
const char *mission_mode(const struct App *app);
unsigned mission_mode_id(const struct App *app);
float ld_decode_radar(int16_t raw);
bool ld_debit_fuel(Mission *m, uint32_t amount);
bool ld_touchdown(Mission *m);
bool ld_profile(Mission *m, const uint16_t *profile, size_t count);
void ld_guidance(struct App *app);
void ld_navigation(struct App *app);
bool mission_nominal_check(const struct App *app);
void mission_report(const struct App *app);
void mission_shutdown(struct App *app);
#endif
