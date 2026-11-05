#include "services.h"
#include <string.h>

IoStatus journal_patch(Platform *p, size_t page, size_t offset,
                       const uint8_t *data, size_t size)
{
    if (page >= FLASH_SIZE / FLASH_PAGE || offset >= FLASH_PAGE) {
        return IO_RANGE;
    }
    return platform_program(p, page * FLASH_PAGE + offset, data, size);
}

IoStatus journal_append(Journal *j, Platform *p, const Event *event)
{
    if (!event) {
        return IO_INVALID;
    }
    uint8_t record[16] = {0};
    write_be16(record, 0x5343u);
    write_be16(record + 2, event->code);
    record[4] = (uint8_t)(event->timestamp >> 24);
    record[5] = (uint8_t)(event->timestamp >> 16);
    record[6] = (uint8_t)(event->timestamp >> 8);
    record[7] = (uint8_t)event->timestamp;
    uint32_t value = (uint32_t)event->value;
    record[8] = (uint8_t)(value >> 24);
    record[9] = (uint8_t)(value >> 16);
    record[10] = (uint8_t)(value >> 8);
    record[11] = (uint8_t)value;
    write_be16(record + 12, j->version);
    write_be16(record + 14, crc16(record, 14));
    size_t page = j->next_page % (FLASH_SIZE / FLASH_PAGE);
    IoStatus status = platform_erase(p, page);
    if (status != IO_OK) {
        return status;
    }
    status = journal_patch(p, page, 0, record, sizeof(record));
    if (status == IO_OK) {
        ++j->writes;
        ++j->next_page;
    }
    return status;
}

bool journal_read(Platform *p, size_t page, Event *event)
{
    if (!event || page >= FLASH_SIZE / FLASH_PAGE) {
        return false;
    }
    const uint8_t *r = p->flash + page * FLASH_PAGE;
    if (read_be16(r) != 0x5343u || read_be16(r + 14) != crc16(r, 14)) {
        return false;
    }
    event->code = read_be16(r + 2);
    event->timestamp = ((uint32_t)r[4] << 24) | ((uint32_t)r[5] << 16) |
                       ((uint32_t)r[6] << 8) | r[7];
    uint32_t value = ((uint32_t)r[8] << 24) | ((uint32_t)r[9] << 16) |
                      ((uint32_t)r[10] << 8) | r[11];
    event->value = (int32_t)value;
    return true;
}
