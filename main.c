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
#include"ethernet.h"
#include"IP.h"
#include"TCP.h"
#include"UDP.h"
#include"ICMP.h"
#include"ARP.h"

void analyze_ICMP(BYTE* data,int size){
	struct ICMP_data mes;
	
	printf("\t\t<ICMP>\n");
	{
		int res;
		res=ICMP_parse(data,size,&mes);
		if(res==-1){
			printf("\t\tBad packet.\n");
		}
	}
	
	printf("\t\ttype:     %d(%s)\n",
		mes.type,
		ICMP_messageName(mes.type)
		);
	printf("\t\tcode:     %d\n",mes.code);
	printf("\t\tchecksum: %d\n",mes.checksum);
	switch(mes.type){
	case 0:
	case 8:
		printf("\t\tid:       %d\n",mes.echo.id);
		printf("\t\tseq:      %d\n",mes.echo.seq);
		free(mes.echo.data);
		break;
	default:
		free(mes.data);
	}
}

void analyze_UDP(BYTE* data,int size){
	struct UDP_datagram dgram;

	printf("\t\t<UDP>\n");
	{
		int res;
		res=UDP_parse(data,size,&dgram);
		if(res==-1){
			printf("\t\tBad packet.\n");
			return ;
		}
	}
	printf("\t\tsrcport:  %d\n",dgram.srcport);
	printf("\t\tdstport:  %d\n",dgram.dstport);
	printf("\t\tlength:   %d\n",dgram.length);
	printf("\t\tchecksum: %d\n",dgram.checksum);

	free(dgram.payload);
}

void analyze_TCP(BYTE* data,int size){
	struct TCP_segment segment;
	printf("\t\t<TCP>\n");
	{
		int res;
		res = TCP_parse(data,size,&segment);
		if(res==-1){
			printf("\t\tBad packet.\n");
			return;
		}
	}
	printf("\t\tsrcport:        %d\n",segment.srcport);
	printf("\t\tdstport:        %d\n",segment.dstport);
	printf("\t\tseq:            %u\n",segment.seq);
	printf("\t\tack:            %u\n",segment.ack);
	printf("\t\theader_length:  %d\n",segment.header_length);
	printf("\t\tflags:\n");
	printf("\t\t   NS:             %d\n",segment.flags.NS);
	printf("\t\t  CWR:             %d\n",segment.flags.CWR);
	printf("\t\t  ECE:             %d\n",segment.flags.ECE);
	printf("\t\t  URG:             %d\n",segment.flags.URG);
	printf("\t\t  ACK:             %d\n",segment.flags.ACK);
	printf("\t\t  PSH:             %d\n",segment.flags.PSH);
	printf("\t\t  RST:             %d\n",segment.flags.RST);
	printf("\t\t  SYN:             %d\n",segment.flags.SYN);
	printf("\t\t  FIN:             %d\n",segment.flags.FIN);
	printf("\t\twindow:         %d\n",segment.window);
	printf("\t\tchecksum:       0x%X\n",segment.checksum);
	printf("\t\turgent_pointer: 0x%X\n",segment.urgent_pointer);

	free(segment.payload);
}

void analyze_IP(BYTE* data,int size){
	struct IP_packet packet;
	printf("\t<IP>\n");
	{
		int res;
		res=IP_parse(
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
			IP_protocolName(packet.protocol)
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
	switch(packet.protocol){
	case 0x1:
		analyze_ICMP(
				packet.payload,
				packet.total_length-packet.header_length*4
				);
		break;
	case 0x6:
		analyze_TCP(
				packet.payload,
				packet.total_length-packet.header_length*4
				);
		break;
	case 0x11:
		analyze_UDP(
				packet.payload,
				packet.total_length-packet.header_length*4
				);
		break;
	}
	free(packet.payload);
}

void analyze_ARP(BYTE* data,int size){
	struct ARP_data mes;
	printf("\t<ARP>\n");
	{
		int res;
		res=ARP_parse(data,size,&mes);
		if(res==-1){
			printf("Bad packet.\n");
			return ;
		}
	}
	printf("\tHardware Type:           0x%X\n",mes.hardware_type);
	printf("\tProtocol Type:           0x%X\n",mes.protocol_type);
	printf("\tHardware Address Length: %d\n",
		mes.hardware_address_length);
	printf("\tProtocol Address Length: %d\n",
		mes.protocol_address_length);
	printf("\tOperation:               0x%X\n",mes.operation);
	printf("\tsender hardware address: ");
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
		((BYTE*)&mes.sender_hardware_address)[5],
		((BYTE*)&mes.sender_hardware_address)[4],
		((BYTE*)&mes.sender_hardware_address)[3],
		((BYTE*)&mes.sender_hardware_address)[2],
		((BYTE*)&mes.sender_hardware_address)[1],
		((BYTE*)&mes.sender_hardware_address)[0]
		);
	printf("\tsender protocol address: %d.%d.%d.%d\n",
			((BYTE*)&mes.sender_protocol_address)[3],
			((BYTE*)&mes.sender_protocol_address)[2],
			((BYTE*)&mes.sender_protocol_address)[1],
			((BYTE*)&mes.sender_protocol_address)[0]
			);
	printf("\ttarget hardware address: ");
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
		((BYTE*)&mes.target_hardware_address)[5],
		((BYTE*)&mes.target_hardware_address)[4],
		((BYTE*)&mes.target_hardware_address)[3],
		((BYTE*)&mes.target_hardware_address)[2],
		((BYTE*)&mes.target_hardware_address)[1],
		((BYTE*)&mes.target_hardware_address)[0]
		);
	printf("\ttarget protocol address: %d.%d.%d.%d\n",
			((BYTE*)&mes.target_protocol_address)[3],
			((BYTE*)&mes.target_protocol_address)[2],
			((BYTE*)&mes.target_protocol_address)[1],
			((BYTE*)&mes.target_protocol_address)[0]
			);
}

void analyze(BYTE* data,int size){
	struct ethernet_frame frame;
	{
		int res=ethernet_parse(data,size,&frame);
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
		ethernet_protocolName(frame.type)
		);
	printf("length:  %d\n",frame.length);
	switch(frame.type){
	case 0x800:
		analyze_IP(frame.payload,frame.length);
		break;
	case 0x806:
		analyze_ARP(frame.payload,frame.length);
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
		BYTE data[ETH_HLEN+ETH_DATA_LEN+10000];
		size=recv(sock_r,data,sizeof(data),0);
		analyze(data,size);
	}
}
