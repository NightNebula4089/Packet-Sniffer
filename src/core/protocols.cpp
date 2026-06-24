#include "PacketFactory.h"
#include "ipv4_packet.h"
#include "ipv6_packet.h"
#include "arp_packet.h"
#include "tcp_packet.h"
#include "udp_packet.h"
#include "icmp_packet.h"

void registerAllProtocols() {
    auto& f = PacketFactory::instance();

    // EtherTypes
    f.registerEtherType(0x0800, [](PayloadView v){ return std::make_unique<Ipv4Packet>(v); });
    f.registerEtherType(0x86DD, [](PayloadView v){ return std::make_unique<Ipv6Packet>(v); });
    f.registerEtherType(0x0806, [](PayloadView v){ return std::make_unique<ArpPacket>(v);  });

    // IP protocol numbers
    f.registerIpProto(0x06, [](PayloadView v){ return std::make_unique<TcpPacket>(v);  });
    // f.registerIpProto(0x11, [](PayloadView v){ return std::make_unique<UdpPacket>(v);  });
    f.registerIpProto(0x01, [](PayloadView v){ return std::make_unique<IcmpPacket>(v); });
}