#include<stdlib.h>
#include<string.h>
#include"types.h"
#include"util.h"
#include"UDP.h"

int UDP_parse(BYTE* data,int size,struct UDP_datagram* res){
	if(size < 8)return -1;
	reverseAndCopy(&res->srcport,data+0,2);
	reverseAndCopy(&res->dstport,data+2,2);
	reverseAndCopy(&res->length,data+4,2);
	reverseAndCopy(&res->checksum,data+6,2);

	if(size < res->length)return -1;

	res->payload=(BYTE*)malloc(res->length-8);
	if(res->payload==0)return -1;

	memcpy(
		res->payload,
		data+8,
		res->length-8
		);
	return 0;
}
