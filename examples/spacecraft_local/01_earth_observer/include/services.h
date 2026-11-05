#ifndef SERVICES_H
#define SERVICES_H
#include "platform.h"
#define COMMAND_CAPACITY 64u
#define QUEUE_CAPACITY 12u
#define EVENT_CAPACITY 32u
#define TASK_CAPACITY 12u
typedef struct {
    uint16_t opcode;
    uint16_t sequence;
    uint16_t length;
    uint8_t payload[COMMAND_CAPACITY];
} Command;
typedef struct {
    Command entries[QUEUE_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    uint32_t dropped;
} CommandQueue;
typedef struct {
    uint32_t timestamp;
    uint16_t code;
    int32_t value;
} Event;
typedef struct {
    Event entries[EVENT_CAPACITY];
    size_t head;
    size_t count;
    uint32_t total;
} EventLog;
typedef struct {
    uint32_t last_kick;
    uint32_t timeout;
    uint32_t trips;
    bool armed;
} Watchdog;
typedef void (*TaskFunction)(void *context);
typedef struct {
    const char *name;
    TaskFunction run;
    uint32_t period;
    uint32_t last_run;
    uint32_t executions;
    uint32_t missed;
    bool enabled;
} Task;
typedef struct {
    Task tasks[TASK_CAPACITY];
    size_t count;
    void *context;
} Scheduler;
typedef struct {
    uint16_t id;
    uint16_t version;
    uint32_t writes;
    size_t next_page;
} Journal;
typedef struct {
    float voltage;
    float charge;
    float temperature;
    float load_watts;
    bool payload_enabled;
    bool heater_enabled;
    uint32_t shed_count;
} Power;
typedef struct {
    uint32_t accepted;
    uint32_t rejected;
    uint32_t packets;
    uint32_t tx_failed;
    uint16_t last_sequence;
    bool sequence_valid;
    char label[80];
} Link;
void queue_init(CommandQueue *q);
bool queue_push(CommandQueue *q, const Command *command);
bool queue_pop(CommandQueue *q, Command *command);
void event_add(EventLog *log, uint32_t now, uint16_t code, int32_t value);
bool event_get(const EventLog *log, size_t age, Event *out);
bool packet_decode(const uint8_t *frame, size_t size, Command *command);
size_t packet_encode(uint8_t *frame, size_t capacity, const Command *command);
bool link_receive(Link *link, CommandQueue *q, const uint8_t *frame, size_t size);
IoStatus link_status(Link *link, Platform *p, unsigned mode, float charge);
void watchdog_init(Watchdog *w, uint32_t now, uint32_t timeout);
void watchdog_kick(Watchdog *w, uint32_t now);
bool watchdog_poll(Watchdog *w, uint32_t now);
void scheduler_init(Scheduler *s, void *context);
bool scheduler_add(Scheduler *s, const char *name, TaskFunction run,
                   uint32_t period, uint32_t now);
void scheduler_run(Scheduler *s, uint32_t now);
IoStatus journal_patch(Platform *p, size_t page, size_t offset,
                       const uint8_t *data, size_t size);
IoStatus journal_append(Journal *j, Platform *p, const Event *event);
bool journal_read(Platform *p, size_t page, Event *event);
void power_init(Power *power);
void power_update(Power *power, Platform *p, float dt);
bool power_request(Power *power, float watts);
#endif
