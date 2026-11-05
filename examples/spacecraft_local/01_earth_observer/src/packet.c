#include "services.h"
#include <string.h>

/* Local simulator framing: opcode, sequence, length, payload, CRC16. */
bool packet_decode(const uint8_t *frame, size_t size, Command *command)
{
    if (!frame || !command || size < 8u) {
        return false;
    }
    uint16_t length = read_be16(frame + 4);
    if (length > 192u || size != (size_t)length + 8u) {
        return false;
    }
    if (crc16(frame, size - 2u) != read_be16(frame + size - 2u)) {
        return false;
    }
    command->opcode = read_be16(frame);
    command->sequence = read_be16(frame + 2);
    command->length = length;
    memcpy(command->payload, frame + 6, length);
    return true;
}

size_t packet_encode(uint8_t *frame, size_t capacity, const Command *command)
{
    if (!frame || !command || command->length > COMMAND_CAPACITY) {
        return 0;
    }
    size_t total = (size_t)command->length + 8u;
    if (capacity < total) {
        return 0;
    }
    write_be16(frame, command->opcode);
    write_be16(frame + 2, command->sequence);
    write_be16(frame + 4, command->length);
    memcpy(frame + 6, command->payload, command->length);
    write_be16(frame + total - 2u, crc16(frame, total - 2u));
    return total;
}

bool link_receive(Link *link, CommandQueue *q, const uint8_t *frame, size_t size)
{
    Command command = {0};
    if (!packet_decode(frame, size, &command)) {
        ++link->rejected;
        return false;
    }
    uint16_t delta = (uint16_t)(command.sequence - link->last_sequence);
    if (link->sequence_valid && (delta == 0 || delta >= 0x8000u)) {
        ++link->rejected;
        return false;
    }
    if (!queue_push(q, &command)) {
        ++link->rejected;
        return false;
    }
    link->last_sequence = command.sequence;
    link->sequence_valid = true;
    ++link->accepted;
    return true;
}
