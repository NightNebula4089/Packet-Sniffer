#ifndef CAPTURED_PACKET_H
#define CAPTURED_PACKET_H

#include "Packet.h"
#include <pcap.h>

struct CapturedPacket {
    struct timeval timestamp;
    uint32_t capture_len;

    std::vector<std::unique_ptr<Packet>> layers;

    EthernetPacket* ethernet() const {
        for (const auto& layer : layers) {
            if (auto eth = dynamic_cast<EthernetPacket*>(layer.get())) {
                return eth;
            }
        }
        return nullptr;
    }

    Ipv4Packet* ipv4() const {getLayer<Ipv4Packet>();}
    Ipv6Packet* ipv6() const {getLayer<Ipv6Packet>();}
    TcpPacket* tcp() const {getLayer<TcpPacket>();}
    UdpPacket* udp() const {getLayer<UdpPacket>();}
    IcmpPacket* icmp() const {getLayer<IcmpPacket>();}

    private :
        template<typename T>
        T* getLayer() const {
            for (const auto& layer : layers) {
                if (auto specific_layer = dynamic_cast<T*>(layer.get())) {
                    return specific_layer;
                }
            }
            return nullptr;
        }

};