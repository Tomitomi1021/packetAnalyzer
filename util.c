#include<stddef.h>

void reverseAndCopy(void* dst,void* src,size_t size){
	for(int i=0;i<size;i++){
		((char*)dst)[size-i-1]=((char*)src)[i];
	}
}
