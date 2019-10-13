struct TCP_segment{
	WORD srcport;
	WORD dstport;
	DWORD seq;
	DWORD ack;
	BYTE header_length;
	struct {
		BYTE NS;
		BYTE CWR;
		BYTE ECE;
		BYTE URG;
		BYTE ACK;
		BYTE PSH;
		BYTE RST;
		BYTE SYN;
		BYTE FIN;
	} flags;
	WORD window;
	WORD checksum;
	WORD urgent_pointer;
	BYTE options[40];
	BYTE* payload;
};

int TCP_parse(BYTE* data,int size,struct TCP_segment* res);
