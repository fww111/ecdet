#include "app.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

static void fast_task(void *context)
{
    App *app = context;
    mission_fast(app);
    ++app->heartbeat;
}

static void mission_task(void *context)
{
    mission_slow(context);
}

static void command_task(void *context)
{
    app_dispatch(context);
}

static void power_task(void *context)
{
    App *app = context;
    power_update(&app->power, &app->platform, 0.5f);
}

static void telemetry_task(void *context)
{
    App *app = context;
    (void)link_status(&app->link, &app->platform,
                      mission_mode_id(app), app->power.charge);
}

static void health_task(void *context)
{
    App *app = context;
    if (watchdog_poll(&app->watchdog, app->platform.tick_ms)) {
        ++app->health_faults;
        event_add(&app->events, app->platform.tick_ms, 10, -1);
    }
    if (!isfinite(app->power.charge) || app->power.voltage < 22.0f) {
        ++app->health_faults;
        event_add(&app->events, app->platform.tick_ms, 11, -1);
    }
}

static void storage_task(void *context)
{
    App *app = context;
    Event event;
    if (app->persisted_event == app->events.total ||
        !event_get(&app->events, 0, &event)) {
        return;
    }
    if (journal_append(&app->journal, &app->platform, &event) == IO_OK) {
        app->persisted_event = app->events.total;
    } else {
        ++app->health_faults;
    }
}

bool app_init(App *app, uint32_t seed)
{
    memset(app, 0, sizeof(*app));
    platform_init(&app->platform, seed);
    queue_init(&app->commands);
    scheduler_init(&app->scheduler, app);
    power_init(&app->power);
    watchdog_init(&app->watchdog, 0, 500);
    app->journal.version = 1;
    (void)snprintf(app->link.label, sizeof(app->link.label), "SC-SIM");
    mission_init(app);
    bool ok = true;
    ok &= scheduler_add(&app->scheduler, "commands", command_task, 100, 0);
    ok &= scheduler_add(&app->scheduler, "fast-control", fast_task, 100, 0);
    ok &= scheduler_add(&app->scheduler, "power", power_task, 500, 0);
    ok &= scheduler_add(&app->scheduler, "mission", mission_task, 500, 0);
    ok &= scheduler_add(&app->scheduler, "health", health_task, 200, 0);
    ok &= scheduler_add(&app->scheduler, "telemetry", telemetry_task, 1000, 0);
    ok &= scheduler_add(&app->scheduler, "storage", storage_task, 1000, 0);
    event_add(&app->events, 0, 1, ok ? 1 : -1);
    return ok;
}

bool app_ingest(App *app, const uint8_t *frame, size_t size)
{
    return link_receive(&app->link, &app->commands, frame, size);
}

void app_dispatch(App *app)
{
    Command command;
    unsigned budget = 4;
    while (budget-- > 0 && queue_pop(&app->commands, &command)) {
        bool ok = false;
        switch (command.opcode) {
        case 1:
            ok = command.length == 0;
            break;
        case 2:
            if (command.length < sizeof(app->link.label)) {
                memcpy(app->link.label, command.payload, command.length);
                app->link.label[command.length] = '\0';
                ok = true;
            }
            break;
        case 3:
            if (command.length == 2) {
                ok = power_request(&app->power, (float)read_be16(command.payload));
            }
            break;
        case 4:
            if (command.length >= 4) {
                size_t page = read_be16(command.payload);
                size_t offset = read_be16(command.payload + 2);
                ok = journal_patch(&app->platform, page, offset,
                                   command.payload + 4, command.length - 4u) == IO_OK;
            }
            break;
        default:
            ok = mission_command(app, &command);
            break;
        }
        if (ok) {
            ++app->dispatch_ok;
        } else {
            ++app->dispatch_failed;
        }
        event_add(&app->events, app->platform.tick_ms, ok ? 2 : 3, command.opcode);
    }
}

void app_tick(App *app, uint32_t delta)
{
    platform_advance(&app->platform, delta);
    scheduler_run(&app->scheduler, app->platform.tick_ms);
}

bool app_nominal_check(const App *app)
{
    if (!mission_nominal_check(app) || app->heartbeat == 0 || app->link.packets == 0 ||
        app->journal.writes == 0 || app->dispatch_ok == 0 ||
        app->health_faults != 0 || app->commands.count != 0) {
        return false;
    }
    if (!isfinite(app->power.charge) || app->power.charge < 0.0f ||
        app->power.charge > 100.0f) {
        return false;
    }
    for (size_t i = 0; i < app->scheduler.count; ++i) {
        if (app->scheduler.tasks[i].executions == 0) {
            return false;
        }
    }
    return true;
}

void app_report(const App *app)
{
    mission_report(app);
    printf("mode=%s ticks=%lu heartbeat=%lu charge=%.3f\n",
           mission_mode(app), (unsigned long)app->platform.tick_ms,
           (unsigned long)app->heartbeat, (double)app->power.charge);
    printf("accepted=%lu rejected=%lu dispatched=%lu failed=%lu\n",
           (unsigned long)app->link.accepted, (unsigned long)app->link.rejected,
           (unsigned long)app->dispatch_ok, (unsigned long)app->dispatch_failed);
    printf("telemetry=%lu flash_records=%lu events=%lu health_faults=%lu\n",
           (unsigned long)app->link.packets, (unsigned long)app->journal.writes,
           (unsigned long)app->events.total, (unsigned long)app->health_faults);
    for (size_t i = 0; i < app->scheduler.count; ++i) {
        const Task *t = &app->scheduler.tasks[i];
        printf("task=%s executions=%lu missed=%lu\n", t->name,
               (unsigned long)t->executions, (unsigned long)t->missed);
    }
}
