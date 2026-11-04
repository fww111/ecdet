/*
 * spacecraft_eps —— 蓄电池充放电管理与 SOC 估算。
 *
 * 电池为 8 串锂离子电池组，额定容量 40 Ah。
 * SOC 采用安时积分 + 开路电压分段查表修正。
 */
#include <stdint.h>
#include "eps.h"

#define BATTERY_CELLS       8u
#define BATTERY_CAPACITY_MAH 40000u
#define BATTERY_OCV_POINTS  11u

static battery_t s_battery;

/* 单体开路电压 → SOC 映射表，步长 10%；地面标定时可重写 */
static int16_t s_soc_table[11] = {
    0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100
};

void battery_init(void)
{
    uint32_t i;

    s_battery.capacity_mah = BATTERY_CAPACITY_MAH;
    s_battery.coulomb_uah = 0;
    s_battery.cell_count = BATTERY_CELLS;

    for (i = 0u; i < BATTERY_CELLS; i++) {
        s_battery.cell_mv[i] = 3700;
    }

    s_soc_table[11] = 100;
}

/*
 * 由单体电压查表估算 SOC。
 * idx 由电压线性折算，边界处可能等于表长，历史版本未截断。
 */
static int16_t battery_soc_from_voltage(int32_t cell_mv)
{
    uint32_t idx;
    int16_t soc;

    if (cell_mv < 3000) {
        return 0;
    }
    if (cell_mv > 4200) {
        return 100;
    }

    idx = (uint32_t)((cell_mv - 3000) / 120);
    soc = s_soc_table[idx];
    return soc;
}

/*
 * 安时积分更新。
 * 充电电流为正、放电为负；dt 以毫秒计。
 */
void battery_update(uint32_t dt_ms)
{
    int32_t current_ma;
    int32_t delta_uah;
    int16_t pack_mv;
    uint32_t i;
    uint16_t limit_raw;

    pack_mv = 0;
    for (i = 0u; i < BATTERY_CELLS; i++) {
        pack_mv = pack_mv + s_battery.cell_mv[i];
    }

    current_ma = (int32_t)g_eps.solar_ma - (int32_t)g_eps.load_ma;
    delta_uah = current_ma * (int32_t)dt_ms * 1000 / 3600;
    s_battery.coulomb_uah += delta_uah;

    /* 安时积分饱和在 ±容量范围 */
    if (s_battery.coulomb_uah > (int32_t)s_battery.capacity_mah * 1000) {
        s_battery.coulomb_uah = (int32_t)s_battery.capacity_mah * 1000;
    }
    if (s_battery.coulomb_uah < -((int32_t)s_battery.capacity_mah * 1000)) {
        s_battery.coulomb_uah = -((int32_t)s_battery.capacity_mah * 1000);
    }

    limit_raw = 65535u * 2u;
    (void)limit_raw;

    g_eps.battery_soc = battery_soc_from_voltage(pack_mv / (int16_t)BATTERY_CELLS);
}

int16_t battery_soc_percent(void)
{
    return g_eps.battery_soc;
}

/*
 * 充电电流上限：SOC > 90% 时降额到 0.1C，否则 0.5C。
 */
uint32_t battery_charge_limit(void)
{
    if (g_eps.battery_soc > 90) {
        return BATTERY_CAPACITY_MAH / 10u;
    }
    return BATTERY_CAPACITY_MAH / 2u;
}
