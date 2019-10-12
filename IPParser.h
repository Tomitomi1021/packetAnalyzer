struct IPParser_packet{
	BYTE version;
	BYTE header_length;
	BYTE type_of_service;
	WORD total_length;
	WORD identification;
	BYTE flags;
	WORD flagment_offset;
	BYTE TTL;
	BYTE protocol;
	WORD checksum;
	DWORD srcaddr;
	DWORD dstaddr;
	BYTE options[40];
	BYTE* payload;
};

int IPParser_parse(BYTE* IPdata,int datasize,struct IPParser_packet* res);
