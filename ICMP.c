#include<string.h>
#include<stdlib.h>
#include"types.h"
#include"util.h"
#include"ICMP.h"

int ICMP_parse(BYTE* data,int size,struct ICMP_data* res){
	if(size<4)return -1;
	res->type=data[0];
	res->code=data[1];
	reverseAndCopy(&res->checksum,data+2,2);

	switch(res->type){
	case 0:
	case 8:
		if(size<8)return -1;
		reverseAndCopy(&res->echo.id,data+4,2);
		reverseAndCopy(&res->echo.seq,data+6,2);
		res->echo.data=(BYTE*)malloc(size-8);
		if(res->echo.data==0)return -1;
		memcpy(
			res->echo.data,
			data+8,
			size-8
			);
		break;
	default:
		res->data=(BYTE*)malloc(size-4);
		if(res->data==0)return -1;
		memcpy(
			res->data,
			data+4,
			size-4
			);
	}
	return 0;
}

char* ICMP_messageName(int type){
	switch(type){
	case  0:return "Echo reply";
	case  3:return "Destination Unreachable";
	case  4:return "Source Quench";
	case  5:return "Redirect";
	case  8:return "Echo request";
	case  9:return "Router Advertisement";
	case 10:return "Router Solicitation";
	case 11:return "Time Exceed";
	case 12:return "Parameter Problem";
	case 13:return "Timestamp";
	case 14:return "Timestamp Reply";
	case 15:return "Information Request";
	case 16:return "Information Reply";
	case 17:return "Address Mask Request";
	case 18:return "Address Mask Reply";
	default:return "Unknown";
	}
}
