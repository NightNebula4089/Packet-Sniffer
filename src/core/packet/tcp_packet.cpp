#include "tcp_packet.h"
#include <iostream>
#include <string.h>
#include <arpa/inet.h>

TcpPacket::TcpPacket(const PayloadInfo& payload_info) : Packet(payload_info) {

    printf("DEBUG TcpPacket: received payload length = %zu\n", payload_info.payload_len);
    printf("DEBUG TcpPacket: first byte = 0x%02x\n", payload_info.payload ? payload_info.payload[0] : 0);

    if (payload_info.payload_len < 20) {
        std::cerr << "Packet too small for TCP header" << std::endl;
        return;
    }

    const u_char* packet = payload_info.payload;

    this->src_port = ntohs(*(uint16_t *)(packet+0));
    this->dst_port = ntohs(*(uint16_t *)(packet+2));
    this->sequence_num = ntohl(*(uint32_t *)(packet+4));
    this->ack_num = ntohl(*(uint32_t *)(packet+8));
    this->data_offset = ((packet[12] >> 4) & 0x0F) * 4;
    this->flags = packet[13];
    this->window_size = ntohs(*(uint16_t *)(packet+14));
    this->checksum = ntohs(*(uint16_t *)(packet+16));
    this->urgent_pointer = ntohs(*(uint16_t *)(packet+18));

    this->payload_info.payload = packet + data_offset;
    this->payload_info.payload_len = payload_info.payload_len - data_offset;
}

TcpPacket::~TcpPacket() {
    // No dynamic memory to free in this implementation
}

std::uint16_t TcpPacket::getProtocol() const {
    return 6; // TCP protocol number
}

void TcpPacket::printInfo() const {
    printf("\033[1;33mTCP Src Port: %d, Dst Port: %d, Sequence Number: %u, Ack Number: %u, Data Offset: %d, Flags: 0x%02x, Window Size: %d, Checksum: 0x%04x, Urgent Pointer: %d\033[0m\n", src_port, dst_port, sequence_num, ack_num, data_offset, flags, window_size, checksum, urgent_pointer);
    printf("\033[1;33mTCP Payload:\033[0m\n");
    for(size_t i = 0; i < payload_info.payload_len; i++){
        printf("%02x ", payload_info.payload[i]);
    }
    printf("\n");
}

ProtoSpace TcpPacket::getProtoSpace() const {
    return ProtoSpace::ApplicationProto;
}

PayloadInfo TcpPacket::getPayload() const {
    PayloadInfo payload_info;
    payload_info.payload = this->payload_info.payload;
    payload_info.payload_len = this->payload_info.payload_len;
    return payload_info;
}