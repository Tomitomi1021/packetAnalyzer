struct ethernet_frame{
	DWORD dstaddr;
	DWORD srcaddr;
	WORD type;
	WORD length;
	BYTE payload[ETH_DATA_LEN+10000];
};

int ethernet_parse(BYTE* ethframe,int datasize,struct ethernet_frame* res);
char* ethernet_protocolName(int type);
