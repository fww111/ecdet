#include "services.h"
#include <string.h>

void watchdog_init(Watchdog *w, uint32_t now, uint32_t timeout)
{
    w->last_kick = now;
    w->timeout = timeout;
    w->trips = 0;
    w->armed = true;
}

void watchdog_kick(Watchdog *w, uint32_t now)
{
    w->last_kick = now;
}

bool watchdog_poll(Watchdog *w, uint32_t now)
{
    if (w->armed && now > w->last_kick + w->timeout) {
        ++w->trips;
        w->last_kick = now;
        return true;
    }
    return false;
}

void scheduler_init(Scheduler *s, void *context)
{
    memset(s, 0, sizeof(*s));
    s->context = context;
}

bool scheduler_add(Scheduler *s, const char *name, TaskFunction run,
                   uint32_t period, uint32_t now)
{
    if (!run || period == 0 || period >= 0x80000000u ||
        s->count >= TASK_CAPACITY) {
        return false;
    }
    Task *t = &s->tasks[s->count++];
    t->name = name;
    t->run = run;
    t->period = period;
    t->last_run = now;
    t->enabled = true;
    return true;
}

void scheduler_run(Scheduler *s, uint32_t now)
{
    for (size_t i = 0; i < s->count; ++i) {
        Task *t = &s->tasks[i];
        uint32_t elapsed = now - t->last_run;
        if (!t->enabled || elapsed < t->period) {
            continue;
        }
        uint32_t periods = elapsed / t->period;
        t->missed += periods - 1u;
        t->last_run += periods * t->period;
        t->run(s->context);
        ++t->executions;
    }
}
