#include "Packet.h"
#include "ethernet_packet.h"
#include "ipv4_packet.h"
#include <iostream>
#include <string.h>
#include <arpa/inet.h>

Ipv4Packet::Ipv4Packet(const PayloadInfo &payload_info) : Packet(payload_info) {

    if (!payload_info.data || payload_info.length < 20) {
        payload_ = { nullptr, 0 };
        return;
    }

    const u_char* h = payload_info.data;

    version_      = (h[0] >> 4) & 0x0F;
    ihl_          =  h[0]       & 0x0F;
    dscp_         = (h[1] >> 2) & 0x3F;
    ecn_          =  h[1]       & 0x03;
    total_length_ = ntohs(*reinterpret_cast<const uint16_t*>(h + 2));
    id_           = ntohs(*reinterpret_cast<const uint16_t*>(h + 4));
    flags_        = (h[6] >> 5) & 0x07;
    frag_offset_  = ntohs(*reinterpret_cast<const uint16_t*>(h + 6)) & 0x1FFF;
    ttl_          = h[8];
    protocol_     = h[9];
    checksum_     = ntohs(*reinterpret_cast<const uint16_t*>(h + 10));
    src_ip_       = ntohl(*reinterpret_cast<const uint32_t*>(h + 12));
    dst_ip_       = ntohl(*reinterpret_cast<const uint32_t*>(h + 16));

    size_t header_len = ihl_ * 4;
    if (header_len > payload_info.length) {
        payload_ = { nullptr, 0 };
        return;
    }

    payload_ = {
        h + header_len,
        total_length_ - header_len   // use the IP total_length, not the frame size
    };
}

Ipv4Packet::~Ipv4Packet() {
    // No dynamic memory to free in this implementation
}

std::uint16_t Ipv4Packet::getProtocol() const {
    return protocol_;
}

void Ipv4Packet::printInfo() const {
    std::cout << "\033[1;33mIPv4 Header:\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Version :  " << std::dec << (int)version_ << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m IHL :  " << std::dec << (int)ihl_ << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m DSCP :  " << std::dec << (int)dscp_ << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m ECN :  " << std    ::dec << (int)ecn_ << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Total Length :  " << std::dec << total_length_ << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Identification :  " << std::dec << id_ << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Flags :  " << std::dec << (int)flags_ << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Fragment Offset :  " << std::dec << frag_offset_ << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m TTL :  " << std::dec << (int)ttl_ << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Protocol :  " << std::dec << (int)protocol_ << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Header Checksum :  " << std::hex << checksum_ << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Source IP :  " << std  ::dec << ((src_ip_ >> 24) & 0xFF) << "." << ((src_ip_ >> 16) & 0xFF) << "." << ((src_ip_ >> 8) & 0xFF) << "." << (src_ip_ & 0xFF) << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Destination IP :  " << std  ::dec << ((dst_ip_ >> 24) & 0xFF) << "." << ((dst_ip_ >> 16) & 0xFF) << "." << ((dst_ip_ >> 8) & 0xFF) << "." << (dst_ip_ & 0xFF) << "\033[0m\n" << std::endl;
}