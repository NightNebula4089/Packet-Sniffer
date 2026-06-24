#ifndef PACKET_FACTORY_H
#define PACKET_FACTORY_H

#include "Packet.h"
#include "ethernet_packet.h"
#include "ipv4_packet.h"
#include "icmp_packet.h"
#include "tcp_packet.h"
#include "udp_packet.h"
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <functional>

using LayerFactory = std::functional<std::unique_ptr<Packet>(PayloadInfo)>;

class PacketFactory{
    public :
        static PacketFactory& instance();
        void registerEtherType(uint16_t type, LayerFactory factory);
        void registerIpProto(uint8_t proto, LayerFactory factory);
        std::unique_ptr<Packet> makeFromEtherType(uint16_t type, PayloadView view) const;
        std::unique_ptr<Packet> makeFromIpProto(uint8_t proto, PayloadView view) const;

    private :
        PacketFactory() = default;
        ~PacketFactory() = default;

        template<typename Key>
        std::unique_ptr<Packet> make(const std::unordered_map<Key, LayerFactory>& factory_map, Key key, PayloadInfo payload_info) const {
            auto it = factory_map.find(key);
            if (it != factory_map.end()) {
                return it->second(payload_info);
            }
            return nullptr; // or throw an exception
        }

        std::unordered_map<std::uint8_t, LayerFactory> ip_factory;
        std::unordered_map<std::uint16_t, LayerFactory> ether_factory;

};