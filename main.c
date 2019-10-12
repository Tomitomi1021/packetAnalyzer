#include<sys/types.h>
#include<sys/socket.h>
#include<linux/if_packet.h>
#include<net/ethernet.h>
#include<netinet/in.h>
#include<unistd.h>
#include<stdio.h>
#include<errno.h>
#include<string.h>
#include<net/ethernet.h>
#include"types.h"
#include"frameParser.h"

struct ethframe{
	struct ethhdr header;
	unsigned char payload[ETH_DATA_LEN+ETH_FCS_LEN];
};

char* protocolNameIP(int type){
	switch(type){
	case 0x1:return "ICMP";
	case 0x2:return "IGMP";
	case 0x6:return "TCP";
	case 0x11:return "UDP";
	default:return "UNKNOWN";
	}
}

char* protocolType(int type){
	switch(type){
	case 0x0800:return "Internet Protocol packet";
	case 0x0806:return "Address Resolution packet";
	default:return "Unknown packet";
	}
}

int main(){
	int sock_r;
	int size;

	sock_r = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	
	if(sock_r<0){
		char* errstr=strerror(errno);
		printf("error in socket\n");
		printf("%s\n",errstr);
		return -1;
	}

	while(1){
		BYTE data[ETH_HLEN+ETH_DATA_LEN+ETH_FCS_LEN];
		struct frameParser_frame frame;
		size=recv(sock_r,data,sizeof(data),0);
		int res=frameParser_parse(data,size,&frame);
		if(res==-1){
			printf("Bad packet.\n");
			continue;
		}
		printf("==========================\n");
		printf("<Ethernet>\n");
		printf("dstaddr: %02X:%02X:%02X:%02X:%02X:%02X\n",
			((BYTE*)&frame.dstaddr)[5],
			((BYTE*)&frame.dstaddr)[4],
			((BYTE*)&frame.dstaddr)[3],
			((BYTE*)&frame.dstaddr)[2],
			((BYTE*)&frame.dstaddr)[1],
			((BYTE*)&frame.dstaddr)[0]
			);
		printf("srcaddr: %02X:%02X:%02X:%02X:%02X:%02X\n",
			((BYTE*)&frame.srcaddr)[5],
			((BYTE*)&frame.srcaddr)[4],
			((BYTE*)&frame.srcaddr)[3],
			((BYTE*)&frame.srcaddr)[2],
			((BYTE*)&frame.srcaddr)[1],
			((BYTE*)&frame.srcaddr)[0]
			);
		printf("type:    0x%X(%s)\n",
			frame.type,
			protocolType(frame.type)
			);
		printf("length:  %d\n",frame.length);
		printf("fcs:     0x%X\n",frame.fcs);
		printf("==========================\n");
	}
}
