#include <stddef.h>
#include <stdint.h>
extern int parse_packet(const uint8_t *, size_t);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)parse_packet(data, size);
    return 0;
}
