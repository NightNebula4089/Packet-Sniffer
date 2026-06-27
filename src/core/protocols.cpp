#include "packet/Packet_factory.h"
#include "packet/ipv4_packet.h"
#include "packet/ipv6_packet.h"
// #include "packet/arp_packet.h"
#include "packet/tcp_packet.h"
#include "packet/udp_packet.h"
#include "packet/icmp_packet.h"

void registerAllProtocols() {
    auto& f = PacketFactory::instance();

    // EtherTypes
    f.registerProto({ProtoSpace::EtherType, 0x0800}, [](PayloadInfo v){ return std::make_unique<Ipv4Packet>(v); });
    f.registerProto({ProtoSpace::EtherType, 0x86DD}, [](PayloadInfo v){ return std::make_unique<Ipv6Packet>(v); });
    // f.registerProto({ProtoSpace::EtherType, 0x0806}, [](PayloadInfo v){ return std::make_unique<ArpPacket>(v);  });

    // IP protocol numbers
    f.registerProto({ProtoSpace::IpProto, 0x06}, [](PayloadInfo v){ return std::make_unique<TcpPacket>(v);  });
    // f.registerProto({ProtoSpace::IpProto, 0x11}, [](PayloadInfo v){ return std::make_unique<UdpPacket>(v);  });
    f.registerProto({ProtoSpace::IpProto, 0x01}, [](PayloadInfo v){ return std::make_unique<IcmpPacket>(v); });
}