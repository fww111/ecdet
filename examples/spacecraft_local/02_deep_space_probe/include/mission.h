#ifndef MISSION_H
#define MISSION_H
#include "services.h"
typedef enum { DS_CRUISE, DS_SCIENCE, DS_CONTACT, DS_SAFE } DsMode;
typedef struct {
    uint32_t due;
    uint16_t opcode;
    uint16_t argument;
    bool executed;
} SequenceStep;
typedef struct {
    DsMode mode;
    SequenceStep steps[8];
    size_t step_count;
    uint8_t assembly[256];
    bool received[256];
    size_t received_count;
    uint8_t *retry_cache;
    size_t retry_size;
    uint32_t retry_at;
    uint32_t bundles_sent;
    uint32_t spectra;
    uint32_t executed;
    uint32_t rejected;
    uint16_t instrument_gain;
    uint16_t bins[16];
    bool instrument_on;
} Mission;
struct App;
void mission_init(struct App *app);
void mission_fast(struct App *app);
void mission_slow(struct App *app);
bool mission_command(struct App *app, const Command *command);
const char *mission_mode(const struct App *app);
unsigned mission_mode_id(const struct App *app);
bool ds_load_sequence(Mission *m, const SequenceStep *steps, size_t count);
bool ds_fragment(Mission *m, uint16_t offset, const uint8_t *data, uint16_t count);
bool ds_instrument_enable(Mission *m);
bool ds_cache(Mission *m, const uint8_t *data, size_t size);
void ds_acknowledge(Mission *m);
void ds_retry(struct App *app);
void ds_sequence_step(struct App *app);
bool mission_nominal_check(const struct App *app);
void mission_report(const struct App *app);
void mission_shutdown(struct App *app);
#endif
