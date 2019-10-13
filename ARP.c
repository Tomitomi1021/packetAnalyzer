#include<stddef.h>
#include"types.h"
#include"util.h"
#include"ARP.h"

int ARP_parse(BYTE* data,int size,struct ARP_data* res){
	if(size<28)return -1;
	reverseAndCopy(&res->hardware_type,data+0,2);
	reverseAndCopy(&res->protocol_type,data+2,2);
	res->hardware_address_length=data[4];
	res->protocol_address_length=data[5];
	reverseAndCopy(&res->operation,data+6,2);
	reverseAndCopy(&res->sender_hardware_address,data+8,6);
	reverseAndCopy(&res->sender_protocol_address,data+14,4);
	reverseAndCopy(&res->target_hardware_address,data+18,6);
	reverseAndCopy(&res->target_protocol_address,data+24,4);
	return 0;
}
