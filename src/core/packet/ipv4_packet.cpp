#include "Packet.h"
#include "ethernet_packet.h"
#include "ipv4_packet.h"
#include <iostream>
#include <string.h>
#include <arpa/inet.h>

Ipv4Packet::Ipv4Packet(const PayloadInfo &payload_info) : Packet(payload_info) {

    if (!payload_info.payload || payload_info.payload_len < 20) {
        this->payload_info = { nullptr, 0 };
        return;
    }

    const u_char* h = payload_info.payload;

    version      = (h[0] >> 4) & 0x0F;
    ihl          =  h[0]       & 0x0F;
    dscp         = (h[1] >> 2) & 0x3F;
    ecn          =  h[1]       & 0x03;
    total_length = ntohs(*reinterpret_cast<const uint16_t*>(h + 2));
    id           = ntohs(*reinterpret_cast<const uint16_t*>(h + 4));
    flags        = (h[6] >> 5) & 0x07;
    frame_offset  = ntohs(*reinterpret_cast<const uint16_t*>(h + 6)) & 0x1FFF;
    ttl          = h[8];
    protocol     = h[9];
    checksum     = ntohs(*reinterpret_cast<const uint16_t*>(h + 10));
    src_ip       = ntohl(*reinterpret_cast<const uint32_t*>(h + 12));
    dst_ip       = ntohl(*reinterpret_cast<const uint32_t*>(h + 16));

    size_t header_len = ihl * 4;
    if (header_len > payload_info.payload_len) {
        this->payload_info = { nullptr, 0 };
        return;
    }

    this->payload_info = {
        h + header_len,
        total_length - header_len   // use the IP total_length, not the frame size
    };
}

Ipv4Packet::~Ipv4Packet() {
    // No dynamic memory to free in this implementation
}

std::uint16_t Ipv4Packet::getProtocol() const {
    return protocol;
}

void Ipv4Packet::printInfo() const {
    std::cout << "\033[1;33mIPv4 Header:\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Version :  " << std::dec << (int)version << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m IHL :  " << std::dec << (int)ihl << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m DSCP :  " << std::dec << (int)dscp << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m ECN :  " << std    ::dec << (int)ecn << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Total Length :  " << std::dec << total_length << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Identification :  " << std::dec << id << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Flags :  " << std::dec << (int)flags << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Frame Offset :  " << std::dec << frame_offset << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m TTL :  " << std::dec << (int)ttl << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Protocol :  " << std::dec << (int)protocol << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Header Checksum :  " << std::hex << checksum << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Source IP :  " << std  ::dec << ((src_ip >> 24) & 0xFF) << "." << ((src_ip >> 16) & 0xFF) << "." << ((src_ip >> 8) & 0xFF) << "." << (src_ip & 0xFF) << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Destination IP :  " << std  ::dec << ((dst_ip >> 24) & 0xFF) << "." << ((dst_ip >> 16) & 0xFF) << "." << ((dst_ip >> 8) & 0xFF) << "." << (dst_ip & 0xFF) << "\033[0m\n" << std::endl;
}

ProtoSpace Ipv4Packet::getProtoSpace() const {
    return ProtoSpace::IpProto;
}

PayloadInfo Ipv4Packet::getPayload() const {
    return this->payload_info;
}