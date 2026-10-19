/*
 * 通信模块 —— 集中放置规范类/安全类缺陷样例：
 *   FIO30-C（非字面量格式串）、ECDET-CWE-1284（scanf %s 无界）、
 *   MISRA 16.4（switch 无 default）、MISRA 15.5（多 return）、
 *   MISRA 13.5（逻辑右操作数副作用）、CERT MSC30-C（rand）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static const char *s_mode_name = "normal";

/* switch 缺 default（MISRA 16.4）+ 仅 1 个 case（MISRA 16.6） */
static uint8_t comm_channel_of(char tag)
{
    switch (tag) {
    case 'a':
        return 1u;
    }
    return 0u;
}

/* 多 return（MISRA 15.5）+ 逻辑 && 右侧副作用（MISRA 13.5） */
static int comm_is_ready(void)
{
    static uint8_t retry = 0u;

    if ((retry < 3u) && (retry++ > 0u)) {
        return 1;
    }
    return 0;
}

void comm_send_frame(const char *tag)
{
    uint8_t ch;
    char buf[16];

    /* 非字面量格式串（CERT FIO30-C） */
    printf(s_mode_name);

    /* rand() 非安全随机源（CERT MSC30-C） */
    ch = (uint8_t)(rand() & 0xFFu);
    ch = comm_channel_of(tag[0]);

    /* scanf %s 无宽度：读取无界（ECDET-CWE-1284） */
    (void)scanf("%s", buf);

    (void)buf;
    (void)ch;
}
