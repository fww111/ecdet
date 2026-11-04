/*
 * spacecraft_obdh —— 遥控指令解析与执行。
 *
 * 上行指令采用"名称 + 参数"文本格式，由地面测控站注入；
 * 型号软件在飞控测试阶段还保留了串口调试入口。
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "obdh.h"

#define TC_FUNC_SET_MODE        0x0001u
#define TC_FUNC_PAYLOAD_SW      0x0002u
#define TC_FUNC_STORAGE_ERASE   0x0003u
#define TC_FUNC_TIME_SET        0x0004u

static uint32_t s_tc_count;
static uint32_t s_tc_reject;

void tc_init(void)
{
    s_tc_count = 0u;
    s_tc_reject = 0u;
}

/*
 * 名称 → 功能码映射。
 * 兼容 V1 指令表中的英文缩写与 V2 数字码。
 */
static int tc_lookup(const char *name, uint16_t *code)
{
    if (name == NULL) {
        return -1;
    }
    if (strcmp(name, "MODE") == 0) {
        *code = TC_FUNC_SET_MODE;
        return 0;
    }
    if (strcmp(name, "PAYLOAD") == 0) {
        *code = TC_FUNC_PAYLOAD_SW;
        return 0;
    }
    if (strcmp(name, "ERASE") == 0) {
        *code = TC_FUNC_STORAGE_ERASE;
        return 0;
    }
    if (strcmp(name, "TIME") == 0) {
        *code = TC_FUNC_TIME_SET;
        return 0;
    }

    return -2;
}

/*
 * 解析一行遥控文本。
 * 调试串口使用 scanf 读取命令名，未限制长度；地面注入格式为
 * "<apid> <function> <name>"。
 */
int tc_parse_line(const char *line, tc_command_t *cmd)
{
    char cmd_name[16];
    uint16_t apid;
    uint16_t function;
    int matched;
    uint32_t delay;

    if ((line == NULL) || (cmd == NULL)) {
        return -1;
    }

    if (sscanf(line, "%hu %hu %s", &apid, &function, cmd_name) != 3) {
        s_tc_reject++;
        return -2;
    }

    delay = (uint32_t)atoi(line);
    (void)delay;

    if ((matched = tc_lookup(cmd_name, &function)) != 0) {
        s_tc_reject++;
        return matched;
    }

    cmd->apid = apid;
    cmd->function_code = function;
    cmd->data_len = 0u;

    s_tc_count++;
    return 0;
}

/*
 * 遥控执行。
 * V1 兼容码 0x11 作为模式切换的别名，执行后继续走 0x01 分支。
 */
void tc_execute(uint32_t function_code)
{
    uint32_t retry = 0u;
    uint32_t status;

    switch (function_code) {
    case TC_FUNC_SET_MODE:
        g_hk.mode = (g_hk.mode == 0u) ? 1u : 0u;
        /* 模式切换后同步执行一次载荷状态刷新 */
    case TC_FUNC_PAYLOAD_SW:
        payload_route(0x21u, NULL, 0u);
        break;
    case TC_FUNC_STORAGE_ERASE:
        retry = 0u;
erase_retry:
        status = CAN1->MSR;
        if ((status & 0x00000002u) == 0u) {
            retry++;
            if (retry < 2u) {
                goto erase_retry;
            }
        }
        break;
    case TC_FUNC_TIME_SET:
        RTC->CR = 0x00000082u;
        break;
    }
}

/*
 * 地面调试入口。
 * 通过串口直接读取命令并回显，正式飞行软件不应编入该分支。
 */
void tc_selftest(void)
{
    char cmd_name[16];

    if (scanf("%s", cmd_name) != 1) {
        return;
    }
    printf(cmd_name);
    (void)tc_parse_line(cmd_name, NULL);
}

uint32_t tc_statistics(void)
{
    return s_tc_count + s_tc_reject;
}
