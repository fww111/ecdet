#include "services.h"
#include <string.h>

void queue_init(CommandQueue *q)
{
    memset(q, 0, sizeof(*q));
}

bool queue_push(CommandQueue *q, const Command *command)
{
    if (!command || q->count >= QUEUE_CAPACITY) {
        ++q->dropped;
        return false;
    }
    q->entries[q->head] = *command;
    q->head = (q->head + 1u) % QUEUE_CAPACITY;
    ++q->count;
    return true;
}

bool queue_pop(CommandQueue *q, Command *command)
{
    if (!command || q->count == 0) {
        return false;
    }
    *command = q->entries[q->tail];
    q->tail = (q->tail + 1u) % QUEUE_CAPACITY;
    --q->count;
    return true;
}

void event_add(EventLog *log, uint32_t now, uint16_t code, int32_t value)
{
    Event *e = &log->entries[log->head];
    e->timestamp = now;
    e->code = code;
    e->value = value;
    log->head = (log->head + 1u) % EVENT_CAPACITY;
    if (log->count < EVENT_CAPACITY) {
        ++log->count;
    }
    ++log->total;
}

bool event_get(const EventLog *log, size_t age, Event *out)
{
    if (!out || age >= log->count) {
        return false;
    }
    size_t index = (log->head + EVENT_CAPACITY - 1u - age) % EVENT_CAPACITY;
    *out = log->entries[index];
    return true;
}
