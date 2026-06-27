#ifndef IPV6_PACKET_H
#define IPV6_PACKET_H

#include "Packet.h"

class Ipv6Packet : public Packet {
    // Implementation for IPv6 packet
    public : 
        explicit Ipv6Packet(const PayloadInfo& payload_info);
        ~Ipv6Packet();
        std::uint16_t getProtocol() const override;
        void printInfo() const override;
        ProtoSpace getProtoSpace() const override;
        PayloadInfo getPayload() const override;
    private :
        unsigned char version;
        unsigned char traffic_class;
        uint32_t flow_label;
        uint16_t payload_length;
        unsigned char next_header;
        unsigned char hop_limit;
        uint32_t src_ip[4];
        uint32_t dst_ip[4];
};

#endif // IPV6_PACKET_H