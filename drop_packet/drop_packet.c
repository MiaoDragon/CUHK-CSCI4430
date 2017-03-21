#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define PACKET_MAX_LEN 65536
#define UDP_HEADER_LEN 8

// Connection State Variable
int state = -1;

// Drop Ratio
double drop_ratio = 0;

/*
 * Callback function installed to netfilter queue
 */
static int Callback(struct nfq_q_handle *myQueue, struct nfgenmsg *msg, 
		struct nfq_data *pkt, void *cbData) {
	unsigned int id = 0;
	struct nfqnl_msg_packet_hdr *header;

	// Get the id of the packets in the queue 
	if ((header = nfq_get_msg_packet_hdr(pkt)))
		id = ntohl(header->packet_id);

	// Read the packet content
	unsigned char *pktData;
	unsigned char *appData;
	int len = nfq_get_payload(pkt, (char**)&pktData);

	// Create Pointers for accessing the IP and UDP header
	struct iphdr *ipHeader = (struct iphdr *) (pktData);
	struct udphdr *udpHeader = (struct udphdr *)(((unsigned char *) ipHeader) + ipHeader->ihl * 4);

	// Read the mode number of the mTCP protocol
	appData = pktData + ipHeader->ihl * 4 + 8;	
	unsigned int mode = appData[0] >> 4;
	
	// Change the state of the connection
	if (mode == 0){
		// If mode = 0, an SYN is detected, the connection is now in 3-way handshake
		state = 0;
	}else if (mode == 5){
		// If mode = 5, an DATA is detected, the connection is now transmitting data
		state = 1;
	}else if (mode == 2){
		// If mode = 2, an DATA is detected, the connection is now in 4-way handshake
		state = 2;
	}

	// Get a random floating point number
	double rand_num = ((double) rand()) / ((double) RAND_MAX);

	if ((state == 1) && (rand_num < drop_ratio)){
		// Drop the packet if the connection is now transmitting data and it is smaller than drop ratio
		printf("state %d mode %d verdict: drop\n", state, mode);
		return nfq_set_verdict(myQueue, id, NF_DROP, 0, NULL);
	}else{
		// Accept other packet
		printf("state %d mode %d verdict: accept\n", state, mode);
		return nfq_set_verdict(myQueue, id, NF_ACCEPT, 0, NULL);
	}
}

/*
 * Main program
 */
int main(int argc, char **argv) {
	struct nfq_handle *nfqHandle;

	struct nfq_q_handle *myQueue;
	struct nfnl_handle *netlinkHandle;

	int fd, res;
	char buf[PACKET_MAX_LEN];

	if (argc == 2){
		drop_ratio = atof(argv[1]);
		srand(time(NULL));
	}else if (argc == 3){
		drop_ratio = atof(argv[1]);
		srand(atoi(argv[2]));
	}else{
		printf("Usage: %s ratio [seed]\n", argv[0]);
		exit(0);
	}

	// Get a queue connection handle from the module
	if (!(nfqHandle = nfq_open())) {
		fprintf(stderr, "Error in nfq_open()\n");
		exit(-1);
	}

	// Unbind the handler from processing any IP packets 
	// (seems to be a must)
	if (nfq_unbind_pf(nfqHandle, AF_INET) < 0) {
		fprintf(stderr, "Error in nfq_unbind_pf()\n");
		exit(1);
	}

	// Bind this handler to process IP packets...
	if (nfq_bind_pf(nfqHandle, AF_INET) < 0) {
		fprintf(stderr, "Error in nfq_bind_pf()\n");
		exit(1);
	}

	// Install a callback on queue 0
	if (!(myQueue = nfq_create_queue(nfqHandle,  0, &Callback, NULL))) {
		fprintf(stderr, "Error in nfq_create_queue()\n");
		exit(1);
	}

	// Turn on packet copy mode
	if (nfq_set_mode(myQueue, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "Could not set packet copy mode\n");
		exit(1);
	}

	netlinkHandle = nfq_nfnlh(nfqHandle);
	fd = nfnl_fd(netlinkHandle);

	while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) {
		nfq_handle_packet(nfqHandle, buf, res);
	}

	nfq_destroy_queue(myQueue);

	nfq_close(nfqHandle);

	return 0;
}

