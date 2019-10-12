#include<sys/types.h>
#include<sys/socket.h>
#include<linux/if_packet.h>
#include<net/ethernet.h>
#include<netinet/in.h>
#include<unistd.h>
#include<stdio.h>
#include<errno.h>
#include<string.h>
#include<stdlib.h>
#include<net/ethernet.h>
#include"types.h"
#include"frameParser.h"
#include"IPParser.h"

struct ethframe{
	struct ethhdr header;
	unsigned char payload[ETH_DATA_LEN+ETH_FCS_LEN];
};

char* protocolName_IP(int type){
	switch(type){
	case 0x1:return "ICMP";
	case 0x2:return "IGMP";
	case 0x6:return "TCP";
	case 0x11:return "UDP";
	default:return "UNKNOWN";
	}
}

char* protocolName_Ethernet(int type){
	switch(type){
	case 0x0800:return "Internet Protocol packet";
	case 0x0806:return "Address Resolution packet";
	default:return "Unknown packet";
	}
}

void analyze_IP(BYTE* data,int size){
	struct IPParser_packet packet;
	printf("\t<IP>\n");
	{
		int res;
		res=IPParser_parse(
					data,
					size,
					&packet
					);
		if(res==-1){
			printf("\tBad packet.\n");
			return;
		}
	}
	printf("\tversion:         %d\n",packet.version);
	printf("\theader_length:   %d\n",packet.header_length);
	printf("\ttype_of_service: 0x%X\n",packet.type_of_service);
	printf("\ttotal_length:    %d\n",packet.total_length);
	printf("\tidentification:  %d\n",packet.identification);
	printf("\tflags:           0x%X\n",packet.flags);
	printf("\tflagment_offset: %d\n",packet.flagment_offset);
	printf("\tTTL:             %d\n",packet.TTL);
	printf("\tprotocol:        0x%X(%s)\n",
			packet.protocol,
			protocolName_IP(packet.protocol)
			);
	printf("\tchecksum:        0x%X\n",packet.checksum);
	printf("\tsrcaddr:         %d.%d.%d.%d\n",
			((BYTE*)&packet.srcaddr)[3],
			((BYTE*)&packet.srcaddr)[2],
			((BYTE*)&packet.srcaddr)[1],
			((BYTE*)&packet.srcaddr)[0]
			);
	printf("\tdstaddr:         %d.%d.%d.%d\n",
			((BYTE*)&packet.dstaddr)[3],
			((BYTE*)&packet.dstaddr)[2],
			((BYTE*)&packet.dstaddr)[1],
			((BYTE*)&packet.dstaddr)[0]
			);
	free(packet.payload);
}

void analyze(BYTE* data,int size){
	struct frameParser_frame frame;
	{
		int res=frameParser_parse(data,size,&frame);
		if(res==-1){
			printf("Bad packet.\n");
			return;
		}
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
		protocolName_Ethernet(frame.type)
		);
	printf("length:  %d\n",frame.length);
//	printf("fcs:     0x%X\n",frame.fcs);
	switch(frame.type){
	case 0x800:
		analyze_IP(frame.payload,frame.length);
		break;
	}
	printf("==========================\n");
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
		size=recv(sock_r,data,sizeof(data),0);
		analyze(data,size);
	}
}
