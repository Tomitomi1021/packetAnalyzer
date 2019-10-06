#include<sys/types.h>
#include<sys/socket.h>
#include<linux/if_packet.h>
#include<net/ethernet.h>
#include<netinet/in.h>
#include<unistd.h>
#include<stdio.h>
#include<errno.h>
#include<string.h>

#define BUFSIZE (1024)

int main(){
	int sock_r;
	char buf[BUFSIZE];
	int size;

	sock_r = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	
	if(sock_r<0){
		char* errstr=strerror(errno);
		printf("error in socket\n");
		printf("%s\n",errstr);
		return -1;
	}

	while(1){
		size=recv(sock_r,buf,BUFSIZE,0);
		for(int i=0;i<size;i++){
			fputc(buf[i],stdout);
		}
	}
}
