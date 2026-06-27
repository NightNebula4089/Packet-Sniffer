#ifndef TCP_PACKET_H
#define TCP_PACKET_H

#include "Packet.h"
#include <string>
#include <pcap.h>
class TcpPacket : public Packet {
    public : 
        TcpPacket(const PayloadInfo& payload_info);
        ~TcpPacket();

        std::uint16_t getProtocol() const override;
        void printInfo() const override;
        ProtoSpace getProtoSpace() const override;
        PayloadInfo getPayload() const override;

    private :
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t sequence_num;
        uint32_t ack_num;
        uint8_t data_offset;
        uint8_t flags;
        uint16_t window_size;
        uint16_t checksum;
        uint16_t urgent_pointer;
};

#endif 