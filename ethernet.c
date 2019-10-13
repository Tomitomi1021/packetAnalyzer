#include<string.h>
#include<linux/if_ether.h>
#include"types.h"
#include"ethernet.h"
#include"util.h"

int ethernet_parse(BYTE* ethframe,int datasize,struct ethernet_frame* res){

	if(datasize<ETH_HLEN)return -1;

	reverseAndCopy(&res->dstaddr,ethframe+0,6);
	reverseAndCopy(&res->srcaddr,ethframe+6,6);

	{
		WORD tmp;
		reverseAndCopy(&tmp,ethframe+12,2);
			if(tmp<=1500){
				res->type=0;
				res->length=tmp;
			}else if(tmp>=1536){
				res->type=tmp;
				res->length=datasize-ETH_HLEN;
			}else{
				res->type=0;
				res->length=datasize-ETH_HLEN;
			}
	}

	if(datasize<ETH_HLEN+res->length)return -1;

	memcpy(&res->payload,ethframe+ETH_HLEN,res->length);

	return 0;
}

char* ethernet_protocolName(int type){
	switch(type){
	case 0x0800:return "Internet Protocol packet";
	case 0x0806:return "Address Resolution packet";
	default:return "Unknown packet";
	}
}
