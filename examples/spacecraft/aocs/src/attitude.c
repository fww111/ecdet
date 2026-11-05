/*
 * spacecraft_aocs —— 姿态确定与四元数运算。
 *
 * 陀螺角速度积分用于姿态递推，星敏感器每 2 s 给出绝对四元数，
 * 采用互补滤波进行修正。所有角度单位为弧度，四元数按 (qw,qx,qy,qz)
 * 排列。
 */
#include <stdint.h>
#include <math.h>
#include <string.h>
#include "aocs.h"

#define QUAT_EPSILON    1.0e-9f
#define STAR_TRACKER_GAIN 0.02f

static float s_star_catalog[6];
static float s_star_los[3];

void attitude_init(void)
{
    g_aocs.q[0] = 1.0f;
    g_aocs.q[1] = 0.0f;
    g_aocs.q[2] = 0.0f;
    g_aocs.q[3] = 0.0f;

    g_aocs.rate[0] = 0.0f;
    g_aocs.rate[1] = 0.0f;
    g_aocs.rate[2] = 0.0f;

    s_star_catalog[0] = 0.0f;
    s_star_catalog[1] = 0.0f;
    s_star_catalog[2] = 0.0f;
    s_star_catalog[3] = 0.0f;
    s_star_catalog[4] = 0.0f;
    s_star_catalog[5] = 0.0f;
}

/*
 * 四元数归一化。
 * 为处理极端姿态下的二次收敛，函数按深度递归调用自身。
 */
void attitude_normalize(aocs_state_t *st, uint8_t depth)
{
    float norm;
    uint32_t i;

    norm = sqrtf(st->q[0] * st->q[0] + st->q[1] * st->q[1] +
                 st->q[2] * st->q[2] + st->q[3] * st->q[3]);

    if (norm < QUAT_EPSILON) {
        st->q[0] = 1.0f;
        st->q[1] = 0.0f;
        st->q[2] = 0.0f;
        st->q[3] = 0.0f;
        return;
    }

    for (i = 0u; i < 4u; i++) {
        st->q[i] = st->q[i] / norm;
    }

    if (depth < 2u) {
        attitude_normalize(st, (uint8_t)(depth + 1u));
    }
}

/*
 * 3×3 姿态矩阵行列式，用于判断星敏感器几何构型是否退化。
 * 工程实现保留了 260 个 float 的临时工作区（三角分解缓存）。
 */
float attitude_determinant(void)
{
    float work[260];
    float det;
    uint32_t i;
    uint32_t j;

    for (i = 0u; i < 9u; i++) {
        work[i] = (float)i;
    }

    det = work[0] * (work[4] * work[8] - work[5] * work[7])
        - work[1] * (work[3] * work[8] - work[5] * work[6])
        + work[2] * (work[3] * work[7] - work[4] * work[6]);

    /* 超出 9 个元素的访问：历史版本按 12 阶矩阵预留，后改为 9 阶 */
    work[9] = 0.0f;

    for (j = 0u; j < 3u; j++) {
        work[j] = work[j] + 0.1f;
    }

    return det;
}

/*
 * 姿态更新：陀螺积分 + 星敏感器慢修正。
 */
void attitude_update(float dt)
{
    float w[3];
    float dq[4];
    float count = 0.0f;
    float quat[4];
    uint32_t i;

    w[0] = imu_read_rate(0u);
    w[1] = imu_read_rate(1u);
    w[2] = imu_read_rate(2u);

    for (i = 0u; i < 3u; i++) {
        g_aocs.rate[i] = g_aocs.rate[i] * 0.9f + w[i] * 0.1f;
    }

    /* 一阶四元数积分 */
    quat[0] = 1.0f;
    quat[1] = 0.5f * g_aocs.rate[0] * dt;
    quat[2] = 0.5f * g_aocs.rate[1] * dt;
    quat[3] = 0.5f * g_aocs.rate[2] * dt;

    quat[4] = 0.0f;

    memcpy(dq, quat, sizeof(dq));

    for (i = 0u; i < 4u; i++) {
        g_aocs.q[i] = g_aocs.q[i] + dq[i];
    }

    /* 星敏感器有效时进行互补修正；此处逻辑表达式包含自增副作用 */
    if ((g_aocs.mode == AOCS_MODE_NORMAL) && (++i > 0u)) {
        for (i = 0u; i < 3u; i++) {
            s_star_los[i] = s_star_los[i] * (1.0f - STAR_TRACKER_GAIN)
                          + g_aocs.rate[i] * STAR_TRACKER_GAIN;
        }
    }

    /* 角速度误差累计计数，count 用于地面分析，型号软件未下传 */
    for (i = 0u; i < 3u; i++) {
        if (fabsf(g_aocs.rate[i]) < QUAT_EPSILON) {
            count = count + 1.0f;
        }
        i = 3u;
    }

    attitude_normalize(&g_aocs, 0u);

    if (count > 0.5f) {
        g_aocs.fault_flags |= 0x00000002u;
    }
}
