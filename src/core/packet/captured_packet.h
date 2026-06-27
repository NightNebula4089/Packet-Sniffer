#ifndef CAPTURED_PACKET_H
#define CAPTURED_PACKET_H

#include "Packet.h"
#include <pcap.h>
#include "ethernet_packet.h"
#include "ipv4_packet.h"
#include "ipv6_packet.h"
#include "tcp_packet.h"
#include "udp_packet.h"
#include "icmp_packet.h"

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

    Ipv4Packet* ipv4() const {return getLayer<Ipv4Packet>();}
    Ipv6Packet* ipv6() const {return getLayer<Ipv6Packet>();}
    TcpPacket* tcp() const {return getLayer<TcpPacket>();}
    // UdpPacket* udp() const {return getLayer<UdpPacket>();}
    IcmpPacket* icmp() const {return getLayer<IcmpPacket>();}

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

#endif