#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h> 
unsigned char* encode(unsigned char* buffer, unsigned int seq, unsigned char mode){
    //pdf shows that it should be htol instead of htonl, but I can not find the header file for htol.
    seq = htonl(seq); 
    memcpy(buffer, &seq, 4);
    buffer[0] = buffer[0] | (mode << 4);
    return buffer;
}

int main(int argc, char **argv){
    return 0;
}
