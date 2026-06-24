#ifndef ICMP_PACKET_H
#define ICMP_PACKET_H

#include "Packet.h"
#include <string>
#include <pcap.h>

class IcmpPacket : public Packet {
    public : 
        IcmpPacket(const PayloadInfo& payload_info);
        ~IcmpPacket();

        std::uint16_t getProtocol() const override;
        void printInfo() const override;

    private :
        unsigned char type;
        unsigned char code;
        uint16_t checksum;
        uint16_t id;
        uint16_t sequence;
}

#endif 