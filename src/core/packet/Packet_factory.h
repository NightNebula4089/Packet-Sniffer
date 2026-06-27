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


struct ProtoKey{
    ProtoSpace space;
    uint32_t key;

    bool operator==(const ProtoKey& other) const {
        return space == other.space && key == other.key;
    }
};

struct ProtoKeyHash{
    std::size_t operator()(const ProtoKey& k) const {
        return std::hash<uint8_t>()(static_cast<uint8_t>(k.space)<< 16  | k.key );
    }
};

using LayerFactory = std::function<std::unique_ptr<Packet>(PayloadInfo)>;

class PacketFactory{
    public :
        static PacketFactory& instance();
        void registerProto(ProtoKey key ,LayerFactory factory);
        
        std::unique_ptr<Packet> makeFromProto(ProtoKey key, PayloadInfo payload) const {
            auto it = registry_.find(key);
            if(it != registry_.end()){
                return it->second(payload);
            } else {
                return nullptr;
            }
        }

    private :
        PacketFactory() = default;
        ~PacketFactory() = default;

        std::unordered_map<ProtoKey, LayerFactory, ProtoKeyHash> registry_;

};

#endif