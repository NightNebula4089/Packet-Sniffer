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

void PacketFactory::registerProto(ProtoKey key, LayerFactory factory) {
    registry_[key] = factory;
}