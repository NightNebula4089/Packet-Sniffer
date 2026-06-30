#include <iostream>
#include <pcap/pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "core/packet/Packet_factory.h"
#include "core/packet/captured_packet.h"
#include "core/packet/Packet.h"

using namespace std;


// forward declarations instead of includes for .cpp files
void registerAllProtocols();
int start_live_capture(string& device, int count, void (*packet_callback)(u_char *, const struct pcap_pkthdr *, const u_char *));
int start_file_capture(const std::string& filename, int count, void (*packet_callback)(u_char *, const struct pcap_pkthdr *, const u_char *));
CapturedPacket parsePacket(const struct pcap_pkthdr* header, const u_char* raw);

void packet_callback(u_char *userinput, const struct pcap_pkthdr *header,const u_char *packet){
    CapturedPacket captured_packet = parsePacket(header, packet);

    cout << "\033[1;34mTimestamp: " << captured_packet.timestamp.tv_sec << "." << captured_packet.timestamp.tv_usec << "\033[0m" << endl;
    for(auto& layer : captured_packet.layers){
        layer->printInfo();
    }
    cout << "END OF PACKET \n" << endl;
}


int main(int argc, char* argv[]){

    // TODO :  Command line argument parsing 

    string device;
    int count = -1;
    int read_file = 0;
    string r_file;
    string w_file;
    int write_file = 0;
    int opt;
    
    while((opt = getopt(argc,argv,"hi:c:r:w:")) != -1){
        switch(opt) {
            case 'i' :
                device = optarg;
                break;
            case 'c' :
                count = atoi(optarg);
                break;
            case 'r' :
                // Handle read file option
                read_file = 1;
                r_file = optarg;
                break;
            case 'w' :
                // Handle write file option
                write_file = 1;
                w_file = optarg;
                break;
            case 'h':
                cout << "Usage" << argv[0] << " i [interface] c [count] r [read_file] w [write_file]" << endl;
                return 0;
            default : 
                cout << "Usage" << argv[0] << " i [interface] c [count] r [read_file] w [write_file]" << endl;
                exit(EXIT_FAILURE);
        }
    }

    registerAllProtocols();

    if(read_file == 1){
        return start_file_capture(r_file, count, packet_callback);
    } else {
        return start_live_capture(device, count, packet_callback);
    }

}