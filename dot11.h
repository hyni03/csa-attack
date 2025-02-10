#ifndef DOT11_H
#define DOT11_H

#include <stdint.h>

#pragma pack(push, 1)

// 802.11 Beacon 프레임 헤더
struct Dot11Header {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t addr1[6];  // 수신자 (Destination)
    uint8_t addr2[6];  // 송신자 (Source)
    uint8_t addr3[6];  // BSSID
    uint16_t seq_ctrl;
};

// Beacon 고정 파라미터 (Timestamp, Beacon Interval, Capability Info)
struct BeaconFixedParams {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t cap_info;
};

// CSA (Channel Switch Announcement) 태그 – 태그 id 0x25
struct CSA_Tag {
    uint8_t tag;         // 0x25
    uint8_t len;         // 항상 3
    uint8_t mode;        // 채널 전환 모드 (예: 1)
    uint8_t new_channel; // 새 채널 번호 (동적으로 설정)
    uint8_t count;       // 카운트 값 (예: 3)
};

#pragma pack(pop)

#endif // DOT11_H