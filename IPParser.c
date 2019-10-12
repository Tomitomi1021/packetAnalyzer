#include<stdlib.h>
#include<string.h>
#include"types.h"
#include"util.h"
#include"IPParser.h"

int IPParser_parse(BYTE* IPdata,int datasize,struct IPParser_packet* res){
	res->version=(IPdata[0] & 0xF0) >> 4;
	res->header_length=(IPdata[0] & 0x0F) >> 0;

	if(datasize < res->header_length*4)return -1;

	res->type_of_service=IPdata[1];
	reverseAndCopy(&res->total_length,IPdata+2,2);

	if(datasize < res->total_length)return -1;

	reverseAndCopy(&res->identification,IPdata+4,2);
	res->flags=(IPdata[6] & 0b11100000) >> 5;
	res->flagment_offset=0;
	res->flagment_offset=(IPdata[6] & 0b00011111 ) << 8;
	res->flagment_offset|=IPdata[7];
	res->TTL = IPdata[8];
	res->protocol = IPdata[9];
	reverseAndCopy(&res->checksum,IPdata+10,2);
	reverseAndCopy(&res->srcaddr,IPdata+12,4);
	reverseAndCopy(&res->dstaddr,IPdata+16,4);
	if(res->header_length*4 > 20){
		memcpy(&res->options,IPdata+20,res->header_length*4-20);
	}

	res->payload=(BYTE*)malloc(res->total_length-res->header_length*4);
	if(res->payload==0)return -1;
	memcpy(
		res->payload,
		IPdata+res->header_length*4,
		res->total_length-res->header_length*4
		);
	return 0;
}
