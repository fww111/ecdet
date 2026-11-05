#ifndef APP_H
#define APP_H
#include "mission.h"
typedef struct App {
    Platform platform;
    Mission mission;
    Scheduler scheduler;
    CommandQueue commands;
    EventLog events;
    Watchdog watchdog;
    Journal journal;
    Power power;
    Link link;
    uint32_t dispatch_ok;
    uint32_t dispatch_failed;
    uint32_t health_faults;
    uint32_t persisted_event;
    uint32_t heartbeat;
} App;
bool app_init(App *app, uint32_t seed);
void app_tick(App *app, uint32_t delta);
bool app_ingest(App *app, const uint8_t *frame, size_t size);
void app_dispatch(App *app);
bool app_nominal_check(const App *app);
void app_report(const App *app);
#endif
