#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
void encode(unsigned char* buffer, unsigned int seq, unsigned char mode){
    //pdf shows that it should be htol instead of htonl, but I can not find the header file for htol.
    seq = htonl(seq);
    memcpy(buffer, &seq, 4);
    buffer[0] = buffer[0] | (mode << 4);
}

struct Tuple {
    unsigned int seq;
    unsigned char mode;
};

struct Tuple decode(unsigned char* buffer, unsigned int seq, unsigned char mode){
    mode = buffer[0]>>4;
    buffer[0] = buffer[0] & 0x0F;
    memcpy(&seq, buffer, 4);
    seq = ntohl(seq);
    struct Tuple result = {seq, mode};
    return result;
}
