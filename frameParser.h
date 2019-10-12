struct frameParser_frame{
	DWORD dstaddr;
	DWORD srcaddr;
	WORD type;
	WORD length;
	BYTE payload[ETH_DATA_LEN+10000];
	DWORD fcs;
};

int frameParser_parse(BYTE* ethframe,int datasize,struct frameParser_frame* res);
