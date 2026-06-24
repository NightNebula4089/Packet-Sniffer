#include "ethernet_packet.h"
#include <iostream>
#include <string.h>
#include <arpa/inet.h>

EthernetPacket::EthernetPacket(const struct pcap_pkthd *header, const u_char *packet) : Packet(PayloadInfo{packet, header->len}) {
    const u_char *packet = payload_info.data;
    size_t size = payload_info.len;

    if (size < 14) {
        std::cerr << "Packet too small for Ethernet header" << std::endl;
        return;
    }

    memcpy(dst_mac, packet, 6);
    memcpy(src_mac, packet + 6, 6);
    ether_type = ntohs(*(unsigned short*)(packet + 12));

    ethernet_payload_offset = 14; // Default offset for Ethernet header
    ethernet_payload_len = size - ethernet_payload_offset; // Length of the payload after Ethernet header

    if (ether_type == 0x8100 || ether_type == 0x88A8) { // VLAN tagged frame
        if (size < 18) {
            std::cerr << "Packet too small for VLAN tagged Ethernet header\n" << std::endl;
            return;
        }
        ether_type = ntohs(*(unsigned short*)(packet + 16)); // Update EtherType to the one after VLAN tag
        ethernet_payload_offset += 4; // VLAN tag adds 4 bytes
        ethernet_payload_len -= 4; // VLAN tag takes away 4 bytes
    }

    payload_info = { packet + ethernet_payload_offset, (size_t)ethernet_payload_len }; // Set payload information

}

EthernetPacket::~EthernetPacket() {
    // No dynamic memory to free in this implementation
}

EthernetPacket::getProtocol() const {
    return ether_type;
}

EthernetPacket::printInfo() const {
    switch(ether_type){
        case 0x0800: // IPv4
            std::cout << "\033[1;32mIPv4 packet detected.\033[0m\n" << std::endl;
            std::cout << "\033[1;31m Mac Src :  " << std::hex << *(unsigned int*)src_mac << "\033[0m\n" << std::endl;
            std::cout << "\033[1;31m Mac Dst :  " << std::hex << *(unsigned int*)dst_mac << "\033[0m\n" << std::endl;
            parse_Ipv4(packet + ethernet_payload_offset, ethernet_payload_len);   
            break;
        case 0x0806: // ARP
            std::cout << "\033[1;32mARP packet detected.\033[0m\n" << std::endl;
            std::cout << "\033[1;31m Mac Src :  " << std::hex << *(unsigned int*)src_mac << "\033[0m\n" << std::endl;
            std::cout << "\033[1;31m Mac Dst :  " << std::hex << *(unsigned int*)dst_mac << "\033[0m\n" << std::endl;
            break;
        case 0x86DD: // IPv6
            std::cout << "\033[1;32mIPv6 packet detected.\033[0m\n" << std::endl;
            std::cout << "\033[1;31m Mac Src :  " << std::hex << *(unsigned int*)src_mac << "\033[0m\n" << std::endl;
            std::cout << "\033[1;31m Mac Dst :  " << std::hex << *(unsigned int*)dst_mac << "\033[0m\n" << std::endl;
            parse_Ipv6(packet + ethernet_payload_offset, ethernet_payload_len);
            break;
        default : 
            std::cout << "\033[1;31mUnknown Ethernet Type:\033[0m " << std::hex << ether_type  << "\n" << std::endl;
    }
}

EthernetPacket::getPayload() const {
    return this->payload_info;
}