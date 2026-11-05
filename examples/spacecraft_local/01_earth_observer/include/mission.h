#ifndef MISSION_H
#define MISSION_H
#include "services.h"
typedef enum { EO_BOOT, EO_DETUMBLE, EO_POINT, EO_IMAGE, EO_DOWNLINK, EO_SAFE } EoMode;
typedef struct {
    EoMode mode;
    float angle[3];
    float rate[3];
    float wheel[3];
    float target[3];
    float star_angle[3];
    uint32_t star_timestamp;
    bool star_valid;
    uint32_t mode_since;
    uint32_t images;
    uint32_t downlinked;
    uint32_t rejected;
    uint8_t tile[128];
    size_t tile_size;
    uint16_t pixels[16];
    size_t pixel_count;
    unsigned exposure_ms;
    bool image_ready;
} Mission;
struct App;
void mission_init(struct App *app);
void mission_fast(struct App *app);
void mission_slow(struct App *app);
bool mission_command(struct App *app, const Command *command);
const char *mission_mode(const struct App *app);
unsigned mission_mode_id(const struct App *app);
bool eo_set_wheel(Mission *m, unsigned index, float torque);
bool eo_load_tile(Mission *m, const uint8_t *data, size_t count);
unsigned eo_mean(const uint16_t *pixels, size_t count);
void eo_fuse_star(Mission *m, uint32_t now);
void eo_camera_step(struct App *app);
void eo_attitude_step(struct App *app);
bool mission_nominal_check(const struct App *app);
void mission_report(const struct App *app);
void mission_shutdown(struct App *app);
#endif
