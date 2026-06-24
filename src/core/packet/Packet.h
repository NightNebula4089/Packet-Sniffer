#ifndef PACKET_H
#define PACKET_H

#include <string.h>
#include <pcap.h>


struct PayloadInfo {
    const u_char* payload;
    size_t payload_len;
}

class Packet{
    public : 
        Packet(const struct pcap_pkthd *header, const u_char *packet);
        virtual ~Packet(); 

        const u_char* get_data() const;
        size_t getSize() const;
        
        virtual PayloadInfo getPayLoad() const = 0; // Pure virtual function to get payload information
        virtual std::uint16_t getProtocol() const = 0; // Pure virtual function to get protocol type
        virtual void printInfo() const = 0; // Pure virtual function to print packet information

    protected : 
        PayloadInfo payload_info; // Struct to hold payload information
};

#endif
