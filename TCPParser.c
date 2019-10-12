#include<stdlib.h>
#include<string.h>
#include"types.h"
#include"util.h"
#include"TCPParser.h"

int TCPParser_parse(BYTE* data,int size,struct TCPParser_segment* res){
	if(size < 20)return -1;

	reverseAndCopy(&res->srcport,data+0,2);
	reverseAndCopy(&res->dstport,data+2,2);
	reverseAndCopy(&res->seq,data+4,4);
	reverseAndCopy(&res->ack,data+8,4);
	res->header_length=( data[12] & 0xF0 ) >> 4;
	res->flags.NS=data[12] & 0x01;

	if(size < res->header_length*4)return -1;
	if(res->header_length < 5)return -1;

	res->flags.CWR=!!(data[13] & 0b10000000);
	res->flags.ECE=!!(data[13] & 0b01000000);
	res->flags.URG=!!(data[13] & 0b00100000);
	res->flags.ACK=!!(data[13] & 0b00010000);
	res->flags.PSH=!!(data[13] & 0b00001000);
	res->flags.RST=!!(data[13] & 0b00000100);
	res->flags.SYN=!!(data[13] & 0b00000010);
	res->flags.FIN=!!(data[13] & 0b00000001);
	reverseAndCopy(&res->window,data+14,2);
	reverseAndCopy(&res->checksum,data+16,2);
	reverseAndCopy(&res->urgent_pointer,data+18,2);

	if(res->header_length>5){
		memcpy(res->options,data+20,res->header_length*4-20);
	}

	res->payload=(BYTE*)malloc(size-res->header_length*4);
	if(res->payload==0)return -1;

	memcpy(
		res->payload,
		data+res->header_length*4,
		size-res->header_length*4
		);

	return 0;
}
