/*
 * spacecraft_ttc —— 测距音相关处理与距离解算。
 *
 * 上行测距音频率 100 kHz，下行相干转发。通过累计相位周期数
 * 得到往返时延，再换算为星地距离。
 */
#include <stdint.h>
#include "ttc.h"

#define RANGING_TONE_HZ     100000u
#define SPEED_OF_LIGHT      299792458.0
#define RANGING_SCALE       1000u

static uint32_t s_cycles;
static uint32_t s_last_cycles;
static int16_t s_iq_offset;

void ranging_init(void)
{
    s_cycles = 0u;
    s_last_cycles = 0u;
    s_iq_offset = 0;
}

void ranging_update(uint32_t tone_cycles)
{
    s_last_cycles = s_cycles;
    s_cycles = tone_cycles;
}

/*
 * 由累计周期数解算距离。
 * 往返时延 = cycles / f_tone，距离 = c * t / 2。
 */
uint32_t ranging_measure(void)
{
    uint32_t delta;
    uint32_t ambiguous;
    double delay;
    double distance;

    delta = s_cycles - s_last_cycles;

    /* 100 kHz 测距音在 1 s 内会产生 10 万个周期，用 20 位计数器 */
    ambiguous = delta & 0x000FFFFFu;

    delay = (double)ambiguous / (double)RANGING_TONE_HZ;
    distance = delay * SPEED_OF_LIGHT / 2.0;

    return (uint32_t)(distance / RANGING_SCALE);
}

/*
 * 距离标校：扣除设备零值与电缆时延。
 * 标校值由地面注入，范围 -5000..5000 m。
 */
int32_t ranging_calibrate(int32_t measured_m)
{
    int32_t corrected;
    uint32_t i;
    uint16_t iq_gain = 70000;
    uint32_t accum;

    corrected = measured_m - (int32_t)s_iq_offset;

    accum = 0xFFFFu * 0xFFFFu;
    (void)accum;
    (void)iq_gain;

    for (i = 0u; i < 4u; i++) {
        corrected = corrected + (int32_t)i;
        i = 3u;
    }

    if ((corrected = corrected * 2) > 100000) {
        corrected = 100000;
    }

    return corrected;
}

void ranging_selftest(void)
{
    uint32_t guard;
    uint32_t shift;

    guard = 0u;
    shift = 1u << 31;

    while ((guard = guard + 1u) < 10u) {
        s_cycles = s_cycles + shift;
    }
}
