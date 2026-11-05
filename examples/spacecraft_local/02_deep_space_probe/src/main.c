#include "app.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool parse_number(const char *text, uint32_t *out)
{
    char *end = NULL;
    errno = 0;
    if (!text[0] || text[0] == '-') {
        return false;
    }
    unsigned long value = strtoul(text, &end, 0);
    if (errno || *end || value > UINT32_MAX) {
        return false;
    }
    *out = (uint32_t)value;
    return true;
}

static bool load_frame(App *app, const char *path)
{
    uint8_t frame[256];
    FILE *stream = fopen(path, "rb");
    if (!stream) {
        perror("open frame");
        return false;
    }
    size_t size = fread(frame, 1, sizeof(frame), stream);
    bool ok = !ferror(stream) && feof(stream);
    if (fclose(stream) != 0) {
        ok = false;
    }
    return ok && app_ingest(app, frame, size);
}

int main(int argc, char **argv)
{
    uint32_t ticks = 200;
    uint32_t seed = 42;
    const char *frame_path = NULL;
    bool self_check = false;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--self-check") == 0) {
            self_check = true;
        } else if (strcmp(argv[i], "--ticks") == 0 && i + 1 < argc) {
            if (!parse_number(argv[++i], &ticks) || ticks > 100000u) {
                return 2;
            }
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            if (!parse_number(argv[++i], &seed)) {
                return 2;
            }
        } else if (strcmp(argv[i], "--frame") == 0 && i + 1 < argc) {
            frame_path = argv[++i];
        } else {
            fprintf(stderr, "usage: spacecraft [--ticks N] [--seed N] [--frame FILE] [--self-check]\n");
            return 2;
        }
    }
    App app;
    if (!app_init(&app, seed)) {
        return 3;
    }
    Command ping = {0};
    ping.opcode = 1;
    ping.sequence = 1;
    uint8_t frame[72];
    size_t size = packet_encode(frame, sizeof(frame), &ping);
    if (!app_ingest(&app, frame, size)) {
        return 4;
    }
    if (frame_path && !load_frame(&app, frame_path)) {
        fprintf(stderr, "frame rejected\n");
        return 5;
    }
    for (uint32_t i = 0; i < ticks; ++i) {
        app_tick(&app, 100);
    }
    app_report(&app);
    int result = 0;
    if (self_check) {
        bool ok = app_nominal_check(&app);
        printf("nominal_check=%s\n", ok ? "PASS" : "FAIL");
        result = ok ? 0 : 6;
    }
    mission_shutdown(&app);
    return result;
}
