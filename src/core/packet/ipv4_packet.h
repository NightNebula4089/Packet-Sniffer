#ifndef IPV4_PACKET_H
#define IPV4_PACKET_H

#include "Packet.h"
#include <string>
#include <pcap.h>
class Ipv4Packet : public Packet {
    public : 
        explicit Ipv4Packet(const PayloadInfo& payload_info);
        ~Ipv4Packet();
        std::uint16_t getProtocol() const override;
        void printInfo() const override;
        ProtoSpace getProtoSpace() const override;
        PayloadInfo getPayload() const override;
    private :
        unsigned char version;
        int ipv4_payload_length;
        int ipv4_payload_offset;
        unsigned char ihl;
        unsigned char dscp;
        unsigned char ecn;
        uint16_t total_length;
        uint16_t id;
        unsigned char flags;
        uint16_t frameoffset;
        unsigned char ttl;
        unsigned char protocol;
        uint16_t checksum;
        uint32_t src_ip;
        uint32_t dst_ip;

        PayloadInfo payload_info; // Struct to hold payload information
};


#endif 