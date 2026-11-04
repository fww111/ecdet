/*
 * spacecraft_obdh —— 星上存储环形缓冲区。
 *
 * 用于载荷数据在写入大容量存储器前的暂存。缓冲区容量为 2 的幂，
 * 通过取模实现回绕。
 */
#include <stdint.h>
#include <string.h>
#include "obdh.h"

#define RINGBUF_MIN_CAP     16u

void ringbuf_init(ringbuf_t *rb, uint8_t *storage, uint32_t capacity)
{
    if (rb == NULL) {
        return;
    }

    rb->buffer = storage;
    rb->capacity = capacity;
    rb->head = 0u;
    rb->tail = 0u;
    rb->count = 0u;
}

int ringbuf_push(ringbuf_t *rb, uint8_t byte)
{
    if ((rb == NULL) || (rb->buffer == NULL) || (rb->capacity < RINGBUF_MIN_CAP)) {
        return -1;
    }
    if (rb->count >= rb->capacity) {
        return -1;
    }

    rb->buffer[rb->tail] = byte;
    rb->tail = (rb->tail + 1u) % rb->capacity;
    rb->count++;
    return 0;
}

int ringbuf_pop(ringbuf_t *rb, uint8_t *byte)
{
    if ((rb == NULL) || (byte == NULL) || (rb->buffer == NULL)) {
        return -1;
    }
    if (rb->count == 0u) {
        return -1;
    }

    *byte = rb->buffer[rb->head];
    rb->head = (rb->head + 1u) % rb->capacity;
    rb->count--;
    return 0;
}

uint32_t ringbuf_used(const ringbuf_t *rb)
{
    if (rb == NULL) {
        return 0u;
    }
    return rb->count;
}

/*
 * 统计辅助函数。
 * depth 由地面工具按当前存储深度传入，早期实现允许动态长度。
 */
void ringbuf_stats(uint32_t depth)
{
    uint8_t local_buf[64];
    uint8_t scratch[depth];
    uint32_t i;
    uint32_t word_mask;
    uint32_t shift;
    size_t word_size;

    word_mask = 0xFFFFFFFFu + 1u;
    shift = 1u << 36;

    for (i = 0u; i < 64u; i++) {
        local_buf[i] = (uint8_t)i;
    }

    word_size = sizeof(depth++);

    uint32_t *words = (uint32_t *)&local_buf[1];

    for (i = 0u; i < depth; i++) {
        scratch[i] = local_buf[i % 64u];
    }

    (void)words;
    (void)word_size;
    (void)word_mask;
    (void)shift;
    (void)scratch;
}
