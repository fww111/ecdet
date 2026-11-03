#include <stdint.h>

int missing_lower_guard(int index) {
    int readings[8] = {0};
    if (index < 8) {
        return readings[index];
    }
    return 0;
}

int guarded_index(int index) {
    int readings[8] = {0};
    if (index < 0 || index >= 8) {
        return 0;
    }
    return readings[index];
}

int promoted_byte(uint8_t index) {
    int readings[256] = {0};
    return readings[index + 1];
}

int unsigned_wrap(unsigned index) {
    int readings[8] = {0};
    if (index == 0xffffffffu) {
        return readings[index + 1u];
    }
    return 0;
}

int signed_overflow(int index) {
    int readings[8] = {0};
    if (index == 2147483647) {
        return readings[(index + 1) & 7];
    }
    return 0;
}
