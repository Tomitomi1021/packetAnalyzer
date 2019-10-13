struct UDP_datagram{
	WORD srcport;
	WORD dstport;
	WORD length;
	WORD checksum;
	BYTE* payload;
};

int UDP_parse(BYTE* data,int size,struct UDP_datagram* res);
