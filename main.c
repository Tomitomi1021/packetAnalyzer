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
	case 0x0000:return "";
	case 0x0800:return "Internet Protocol packet";
	case 0x0806:return "Address Resolution packet";
	default:return "Unknown packet";
	}
}

int CRC32(void* bytes,size_t size){
	unsigned int crc32;
	unsigned int CRCTable[256];
	int nLookupIndex;

	crc32=0xFFFFFFFF;
	for(int i=0;i<size;i++){
		nLookupIndex = (crc32 ^ ((char*)bytes)[i]) & 0xFF;
		crc32 = (crc32 >> 8) ^ CRCTable[nLookupIndex];
	}

	crc32 = crc32 ^ 0xFFFFFFFF;
	return crc32;
}

int main(){
	int sock_r;
	struct ethframe f;
	int size;

	sock_r = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	
	if(sock_r<0){
		char* errstr=strerror(errno);
		printf("error in socket\n");
		printf("%s\n",errstr);
		return -1;
	}

	while(1){
		size=recv(sock_r,&f,sizeof(struct ethframe),0);
		printf("------------------------------------\n");
		printf("<<Ethernet>>\n");
		printf("dst: %02x:%02x:%02x:%02x:%02x:%02x\n",
			f.header.h_dest[0],
			f.header.h_dest[1],
			f.header.h_dest[2],
			f.header.h_dest[3],
			f.header.h_dest[4],
			f.header.h_dest[5]
			);
		printf("src: %02x:%02x:%02x:%02x:%02x:%02x\n",
			f.header.h_source[0],
			f.header.h_source[1],
			f.header.h_source[2],
			f.header.h_source[3],
			f.header.h_source[4],
			f.header.h_source[5]
			);
		unsigned short type;
		type=(((char*)&f.header.h_proto)[0] << 8) | ((char*)&f.header.h_proto)[1];
		if(type<=1500){
			printf("len: %d\n",type);
		}else if(type>=1536){
			printf("prt: 0x%X(%s)\n",type,protocolType(type));
			printf("len: %d\n",size-ETH_HLEN-ETH_FCS_LEN);
			unsigned char* fcs = ((char*)&f) + size - ETH_FCS_LEN;
			printf("fcs: 0x%02X%02X%02X%02X\n",fcs[0],fcs[1],fcs[2],fcs[3]);
			if(type==0x800){
				printf("\t<<IP>>\n");
				printf("\tversion:       %d\n",(f.payload[0] & 0xF0) >> 4);
				printf("\theader length: %d\n",f.payload[0] & 0x0F );
				printf("\tservice type:  0x%X\n",f.payload[1]);
				printf("\tall length:    %d\n",(unsigned int)f.payload[2]<<8 | (unsigned int)f.payload[3]);
				printf("\tid:            %d\n",(unsigned int)f.payload[4]<<8 | (unsigned int)f.payload[5]);
				printf("\tflag:          0x%X\n",f.payload[6]>>5);
				printf("\toffset:        %d\n",(unsigned int)(f.payload[6] & 0b00011111) << 8 | (unsigned int)f.payload[7]);
				printf("\tTTL:           %d\n",f.payload[8]);
				printf("\tProtocol:      0x%X(%s)\n",f.payload[9],protocolNameIP(f.payload[9]));
				printf("\tCheckSum:      0x%X%X\n",f.payload[10],f.payload[11]);
				printf("\tSourceIPAddr:  %d.%d.%d.%d\n",f.payload[12],f.payload[13],f.payload[14],f.payload[15]);
				printf("\tDestIPAddr:    %d.%d.%d.%d\n",f.payload[16],f.payload[17],f.payload[18],f.payload[19]);
				switch(f.payload[9]){
				case 0x1:
					printf("\t\t<<ICMP>>\n");
					printf("\t\tType:      0x%X\n",f.payload[20]);
					printf("\t\tCode:      0x%X\n",f.payload[21]);
					printf("\t\tCheckSum:  0x%X%X\n",f.payload[22] | f.payload[23]);
					break;
				case 0x11:
					printf("\t\t<<UDP>>\n");
					printf("\t\tsource port:        %d\n",(unsigned int)f.payload[20]<<8 | (unsigned int)f.payload[21]);
					printf("\t\tdestination port:   %d\n",(unsigned int)f.payload[22]<<8 | (unsigned int)f.payload[23]);
					printf("\t\tlength:             %d\n",(unsigned int)f.payload[24]<<8 | (unsigned int)f.payload[25]);
					printf("\t\tchecksum:           0x%X\n",(unsigned int)f.payload[26]<<8 | (unsigned int)f.payload[27]);
					break;
				case 0x6:
					printf("\t\t<<TCP>>\n");
					printf("\t\tsource port:        %d\n",(unsigned int)f.payload[20]<<8 | (unsigned int)f.payload[21]);
					printf("\t\tdestination port:   %d\n",(unsigned int)f.payload[22]<<8 | (unsigned int)f.payload[23]);
					printf("\t\tseq:		%u\n",
						(unsigned int)f.payload[24]<<24|
						(unsigned int)f.payload[25]<<16|
						(unsigned int)f.payload[26]<<8 |
						(unsigned int)f.payload[27]    
						);
					printf("\t\tack:		%u\n",
						(unsigned int)f.payload[28]<<24|
						(unsigned int)f.payload[29]<<16|
						(unsigned int)f.payload[30]<<8 |
						(unsigned int)f.payload[31]    
						);
					printf("\t\theader size:        %d\n",(f.payload[32]&0xF0)>>4);
					printf("\t\tNS:                 %d\n",!!(f.payload[32]&0x1));
					printf("\t\tCWR:                %d\n",!!(f.payload[33]&0b10000000));
					printf("\t\tECE:                %d\n",!!(f.payload[33]&0b01000000));
					printf("\t\tURG:                %d\n",!!(f.payload[33]&0b00100000));
					printf("\t\tACK:                %d\n",!!(f.payload[33]&0b00010000));
					printf("\t\tPSH:                %d\n",!!(f.payload[33]&0b00001000));
					printf("\t\tRST:                %d\n",!!(f.payload[33]&0b00000100));
					printf("\t\tSYN:                %d\n",!!(f.payload[33]&0b00000010));
					printf("\t\tFIN:                %d\n",!!(f.payload[33]&0b00000001));
					printf("\t\tWindow:             %d\n",(unsigned int)f.payload[34]<<8 | (unsigned int)f.payload[35]);
					printf("\t\tChecksum:           0x%X\n",(unsigned int)f.payload[36]<<8 | (unsigned int)f.payload[37]);
					printf("\t\tEmergency pointer:  0x%X\n",(unsigned int)f.payload[38]<<8 | (unsigned int)f.payload[39]);
					break;
				}
			}else if(type == 0x806){
				printf("\t<<ARP>>\n");
				printf("\tHardware type:           0x%x\n",f.payload[0]<<8 | f.payload[1]);
				printf("\tProtocol type:           0x%x\n",f.payload[2]<<8 | f.payload[3]);
				printf("\tHardware address length: %d\n",f.payload[4]);
				printf("\tProtocol address length: %d\n",f.payload[5]);
				printf("\tOperation:               0x%x\n",f.payload[6]<<8 | f.payload[7]);
				printf("\tSender hardware address: %02X:%02X:%02X:%02X:%02X:%02X\n",
					f.payload[8],
					f.payload[9],
					f.payload[10],
					f.payload[11],
					f.payload[12],
					f.payload[13]
					);
				printf("\tSender protocol address: %d.%d.%d.%d\n",
					f.payload[14],
					f.payload[15],
					f.payload[16],
					f.payload[17]
					);
				printf("\tTarget hardware address: %02X:%02X:%02X:%02X:%02X:%02X\n",
					f.payload[18],
					f.payload[19],
					f.payload[20],
					f.payload[21],
					f.payload[22],
					f.payload[23]
					);
				printf("\tTarget protocol address: %d.%d.%d.%d\n",
					f.payload[24],
					f.payload[25],
					f.payload[26],
					f.payload[27]
					);
			}
		}else{
			printf("type unknown\n");
		}
		printf("------------------------------------\n");
	}
}
