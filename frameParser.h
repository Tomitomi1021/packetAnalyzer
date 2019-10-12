struct ethdata{
	DWORD dstaddr;
	DWORD srcaddr;
	WORD type;
	WORD length;
	BYTE payload[ETH_DATA_LEN];
	DWORD fcs;
};

int parseFrame(BYTE* ethframe,int datasize,struct ethdata* res);
