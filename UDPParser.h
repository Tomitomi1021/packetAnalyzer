struct UDPParser_datagram{
	WORD srcport;
	WORD dstport;
	WORD length;
	WORD checksum;
	BYTE* payload;
};

int UDPParser_parse(BYTE* data,int size,struct UDPParser_datagram* res);
