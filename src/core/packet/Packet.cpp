#include <pcap.h>
#include "Packet.h"
#include <iostream>
#include <string.h>
#include <arpa/inet.h>

Packet::Packet(const PayloadInfo& payload_info) : payload_info(payload_info) {
}

Packet::~Packet() {
    // No dynamic memory to free in this implementation
}

const u_char* Packet::get_data() const {
    return payload_info.payload;
}

size_t Packet::getSize() const {
    return payload_info.payload_len;
}

