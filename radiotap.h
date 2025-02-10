#ifndef RADIOTAP_H
#define RADIOTAP_H

#include <stdint.h>

#pragma pack(push, 1)

// Radiotap 헤더 (최소 8바이트)
struct RadiotapHeader {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    uint32_t present;
};

#pragma pack(pop)

#endif // RADIOTAP_H
