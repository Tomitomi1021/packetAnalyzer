#include<string.h>
#include<linux/if_ehter.h>
#include"types.h"
#include"frameParser.h"

void reverseAndCopy(void* dst,void* src,size_t size){
	for(int i=0;i<size;i++){
		((char*)dst)[size-i-1]=((char*)src)[i];
	}
}

int parseFrame(BYTE* ethframe,int datasize,struct ethdata* res){

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
				res->length=datasize-ETH_HLEN-ETH_FCS_LEN;
			}else{
				res->type=0;
				res->length=datasize-ETH_HLEN-ETH_FCS_LEN;
			}
	}

	if(datasize<ETH_HLEN+res->length+ETH_FCS_LEN)return -1;

	memcpy(&res->payload,ethframe+ETH_HLEN,res->length);

	reverseAndCopy(&res->fcs,ethframe+ETH_HLEN+res->length,4);

	return 0;
}
