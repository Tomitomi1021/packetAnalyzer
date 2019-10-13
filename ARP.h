
struct ARP_data{
	WORD hardware_type;
	WORD protocol_type;
	BYTE hardware_address_length;
	BYTE protocol_address_length;
	WORD operation;
	QWORD sender_hardware_address;
	DWORD sender_protocol_address;
	QWORD target_hardware_address;
	DWORD target_protocol_address;
};

int ARP_parse(BYTE* data,int size,struct ARP_data* res);
