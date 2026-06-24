#include "icmp_packet.h"
#include <iostream>
#include <string.h>
#include <arpa/inet.h>

IcmpPacket::IcmpPacket(const PayloadInfo& payload_info) : Packet(payload_info) {
    if (this->ipv4_payload_length < 8) {
        std::cerr << "Packet too small for ICMP header" << std::endl;
        return;
    }

    const char* payload = (const char*)payload_info.data + this->ipv4_payload_offset; // Start of ICMP header

    this->type = payload[0];
    this->code = payload[1];
    this->checksum = ntohs(*(uint16_t *)(payload+2));
    this->id = ntohs(*(uint16_t *)(payload   + 4));
    this->sequence = ntohs(*(uint16_t *)(payload + 6));
}

IcmpPacket::~IcmpPacket() {
    // No dynamic memory to free in this implementation
}

std::uint16_t IcmpPacket::getProtocol() const {
    return type;
}

void IcmpPacket::printInfo() const {
    printf("\033[1;33mICMP Type: %d, Code : %d, Checksum: 0x%04x, ID: %d, Sequence: %d\033[0m\n", type, code, checksum, id, sequence);
}