
struct ICMP_echo{
	WORD id;
	WORD seq;
	BYTE* data;
};

struct ICMP_data{
	BYTE type;
	BYTE code;
	WORD checksum;
	union{
		BYTE* data;
		struct ICMP_echo echo;
	};
};

int ICMP_parse(BYTE* data,int size,struct ICMP_data* res);
char* ICMP_messageName(int type);
