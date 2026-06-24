#include "packet_factory.h"
#include "ethernet_packet.h"
#include "ipv4_packet.h"
#include "icmp_packet.h"
#include "tcp_packet.h"
#include "udp_packet.h"

PacketFactory& PacketFactory::instance() {
    static PacketFactory factory;
    return factory;
}

void PacketFactory::registerEtherType(uint16_t type, LayerFactory factory) {
    ether_registry_[type] = std::move(factory);
}

void PacketFactory::registerIpProto(uint8_t proto, LayerFactory factory) {
    ip_proto_registry_[proto] = std::move(factory);
}

std::unique_ptr<Packet> PacketFactory::makeFromEtherType(uint16_t type, PayloadView view) const {
    return make(ether_registry_, type, view);
}

std::unique_ptr<Packet> PacketFactory::makeFromIpProto(uint8_t proto, PayloadView view) const {
    return make(ip_proto_registry_, proto, view);
}