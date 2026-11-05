#include "services.h"
#include <stdio.h>

IoStatus link_status(Link *link, Platform *p, unsigned mode, float charge)
{
    char message[48];
    int length = snprintf(message, sizeof(message),
                          "%s mode=%u charge=%.1f tick=%lu",
                          link->label, mode, (double)charge,
                          (unsigned long)p->tick_ms);
    if (length < 0) {
        ++link->tx_failed;
        return IO_INVALID;
    }
    IoStatus status = platform_tx(p, (const uint8_t *)message, (size_t)length);
    if (status == IO_OK) {
        ++link->packets;
    } else {
        ++link->tx_failed;
    }
    return status;
}
