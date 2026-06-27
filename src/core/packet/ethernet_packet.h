#ifndef ETHERNET_PACKET_H
#define ETHERNET_PACKET_H
#include "Packet.h"
#include <string>
#include <pcap.h>

class EthernetPacket : public Packet {
    public : 
        EthernetPacket(const struct PayloadInfo& payload_info);
        ~EthernetPacket();

        std::uint16_t getProtocol() const override;
        void printInfo() const override;
        PayloadInfo getPayload() const override;
        ProtoSpace getProtoSpace() const override;

    private :
        unsigned char dst_mac[6];
        unsigned char src_mac[6];
        unsigned short ether_type;
        int ethernet_payload_offset = 14; // Default offset for Ethernet header
        int ethernet_payload_len; // Length of the payload after Ethernet header
        PayloadInfo payload_info; // Struct to hold payload information
};

#endif 