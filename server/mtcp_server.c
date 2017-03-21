#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "mtcp_server.h"
#include "linked_list_buffer.h"

#define MAX_BUF_SIZE_MTCP 1024

typedef struct Info {
    // 0: 3-way handshake; 1: data transfer; 2: 4-way handshake; 4: fininshed
    // The state of the server it is only modifed in recv thread 
    // It is accessed by both receiving thread and sending thread
    int state;
    // ack_num = seq + len(data)
    // it is the number that the next recieved packet sequence number
    int ack_num;
    
    // The udp socket fd created in scoket() function in server.c
    int sock_fd;

    //  The client addr, which will be assigned value in recv_from in recv_thread
    struct sockaddr_in* client_addr;

    // The lengh of the sockaddr_in struct 
    socklen_t addrlen; 

    // Error code
    int error;
} Info;


/* ThreadID for Sending Thread and Receiving Thread */
static pthread_t send_thread_pid;
static pthread_t recv_thread_pid;

static pthread_cond_t app_thread_sig = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t app_thread_sig_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_cond_t send_thread_sig = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t send_thread_sig_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t info_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t recv_buf_mutex = PTHREAD_MUTEX_INITIALIZER;

/* The Sending Thread and Receive Thread Function */
static void *send_thread();
static void *receive_thread();

// a global info shared by all threads
static Info info;
// head of the list
static node_t* buffer_list_head;

void mtcp_accept(int socket_fd, struct sockaddr_in *client_addr){
    // 0. Init global state viariable since no other threads
    // No need to add lock
    info.state = 0;
    info.ack_num= 0;
    info.sock_fd = socket_fd;
    info.client_addr = client_addr;
    info.addrlen = sizeof(struct sockaddr_in);
    info.error = 0;// no errror
    buffer_list_head = malloc(sizeof(node_t));
    buffer_list_head->next = NULL;

    //printf("[Main thread]: Threads are created\n");
    // 1. create send_thread and receive_thread
    //  don't need to pass thread_param since all info needed is a global variable
    pthread_create(&recv_thread_pid, NULL, receive_thread, NULL);
    pthread_create(&send_thread_pid, NULL, send_thread, NULL);

    // 2. Wait for reciving thread to wake me up
    pthread_mutex_lock(&app_thread_sig_mutex);
    pthread_cond_wait(&app_thread_sig, &app_thread_sig_mutex);
    pthread_mutex_unlock(&app_thread_sig_mutex);
}

// why do we need socket_fd here?
// strlen(global_recvbuf) < MAX_BUF_SIZE = 1024 = buf_len
int mtcp_read(int socket_fd, unsigned char *buf, int buf_len){
    if (info.error) {
        return -1;
    } 

    pthread_mutex_lock(&app_thread_sig_mutex);
    // When the buffer list is not empty, no need to wait
    while (num_of_buffer(buffer_list_head) == 0 && info.state != 3) {
        pthread_cond_wait(&app_thread_sig, &app_thread_sig_mutex);
    } 
    pthread_mutex_unlock(&app_thread_sig_mutex);

    // zero out the buf first
    memset(buf, 0, sizeof(buf));

    int ret = 0;
    pthread_mutex_lock(&recv_buf_mutex);
    node_t* current = buffer_list_head -> next;
    while ( buf_len > 0 && current != NULL){
        if (buf_len < current->msg_len ) {
            memcpy(buf + ret, current->message, buf_len);
            ret += buf_len;
            current->msg_len -= buf_len;
            memmove(current->message, ((current->message)+buf_len), current->msg_len);
            buf_len = 0; 
        } else {
            current = current->next;
            int msg_len = remove_first(buffer_list_head, buf + ret);
            buf_len -= msg_len;
            ret += msg_len;
        } 
    }
    pthread_mutex_unlock(&recv_buf_mutex);

    // If strlen(buf) == 0, the loop in server.c will break
    // mtcp_close will be the next call;
    // whether we should return +1 or not?
    // How to deal with negtive values?

    return ret;
}

void mtcp_close(int socket_fd){

    // Join the two threads.
    pthread_join(send_thread_pid, NULL);
    pthread_join(recv_thread_pid, NULL);

    // Free the buffer list
    if (num_of_buffer(buffer_list_head) != 0) {
        fprintf(stderr, "Error: call mtcp_close before buffer list becomes empty!\n");
    } else {
        free(buffer_list_head);         
    }   

    // Close the udp descriptor
    close(socket_fd);
    info.error = 1;
    //printf("[Main thread] I exit()!\n");
}

// Only receive_thread modifies the info state 
static void *receive_thread(){
    while (1) {
        // 0. recv packet from client.
        unsigned char buffer[MAX_BUF_SIZE_MTCP];
        int ret = recvfrom(info.sock_fd, buffer, MAX_BUF_SIZE_MTCP, 0, 
                (struct sockaddr*)(info.client_addr), &(info.addrlen));
        if (ret == -1) {
            info.error = 1;
        } 

        char print_buf[MAX_BUF_SIZE_MTCP];
        memcpy(print_buf, buffer+4, ret - 4);
        print_buf[ret - 4] = '\0';
        //printf("137 [Recv thread]: buffer is %s\n", print_buf);

        char addr_buf[20];
        inet_ntop(AF_INET, &((info.client_addr)->sin_addr), addr_buf, 20); 
        //printf ("[Recv thread]: In state %d, I recv from %s\n", info.state, addr_buf);
        // 1. Decode packet from buffer
        // get type, seq, message, data_len
        int type = 1, data_len = 0;
        unsigned int seq;
        char message[MAX_BUF_SIZE_MTCP];
        type = buffer[0] >> 4;
        buffer[0] = buffer[0] & 0x0F; 
        memcpy(&seq, buffer, 4);
        seq = ntohl(seq);
        memcpy(message, buffer+4, sizeof(buffer)-4);

        data_len = ret - 4; 
        message[ret - 4] = '\0';
        //printf("message is: %s\n", message);

        //printf("[Recv thread]: Received buffer data length: %d seq num is:%d type is: %d\n",
         //       data_len, seq, type);
        // 2. handle the state change and buffer manipulation
        // Note: no packet loss in 3-way and 4-way handshake
        if (info.state == 0) {
            if (type == 0) {
                // SYN packet received.
                // 1. modify ack number but don't modify the state 
                //printf ("[Recv thread]: SYN received\n");
                pthread_mutex_lock(&info_mutex);
                info.ack_num = 1;
                pthread_mutex_unlock(&info_mutex);

                // 2. wake up send_thread to send SYN-ACK wit ack_num = 1
                pthread_mutex_lock(&send_thread_sig_mutex);
                pthread_cond_signal(&send_thread_sig);
                pthread_mutex_unlock(&send_thread_sig_mutex);

            } else if (type == 4) {
                // ACK packet received. 
                // 1. Change the status here
                //      Next message can be received and saved to buffer
                //printf ("[Recv thread]: ACK received\n");
                pthread_mutex_lock(&info_mutex);
                info.state = 1; // data trasferring state
                pthread_mutex_unlock(&info_mutex);

                // 2. wake up app_thread to coninue its flow 
                pthread_mutex_lock(&app_thread_sig_mutex);
                pthread_cond_signal(&app_thread_sig);
                pthread_mutex_unlock(&app_thread_sig_mutex);

            } else {
                // since no other possibility in 3-way hand shake stage
                fprintf(stderr, "Error: unexpected message type in receive thread, state 0\n");
            } 
        } else if (info.state == 1) {
            if (type == 5) {
                // Data packet received.
                // thorw away out of order packet
                if (seq == info.ack_num) {
                    // 1. change the ack_num that will be sent by the send_thread
                    //printf ("[Recv thread]: Correct DATA received\n");
                    pthread_mutex_lock(&info_mutex);
                    info.ack_num += data_len;
                    pthread_mutex_unlock(&info_mutex);

                    // 2. save data to received buffer
                    // +1 for NULL terminating
                    // Use a linked list to deal with following
                    // 1. mtcp_read() haven't been called
                    // 2. keep receiving messages from client (it is possible since the send_thread is waken up by receive_thread)
                    pthread_mutex_lock(&recv_buf_mutex);
                    push_buffer(buffer_list_head, message, ret - 4);
                    pthread_mutex_unlock(&recv_buf_mutex);
                    
                    // 3. wake up send_thread
                    pthread_mutex_lock(&send_thread_sig_mutex);
                    pthread_cond_signal(&send_thread_sig);
                    pthread_mutex_unlock(&send_thread_sig_mutex);

                    // 4. wake up app_thread to read buffer
                    // Here I endopt a diffrent design with tutorial notes
                    // Tutorial notes, Waking up the app thread is done in the sending thread
                    // This can cause app_thread break the loop.
                    //
                    // Reason:
                    // Since the send thread will be waken up no matter the ack_num
                    // is correct or not. (see below comments for why we need to wake sending_thread up in both cases),
                    // if we don't do anything in the sending thread, the app thread will be waken up and it will
                    // find there is nothing in the buffer and break the loop, which is definetely not desired.
                    // 
                    // Therefore in order to simplify the design of sending thread,
                    // We wake up the app_thread here (in receive_thread). It is ok since the order of waking up send_thread and app_thread
                    // doesn't matter, we don't need to make sure app_thread is waken up in send_thread.(Do you aggree?)
                    pthread_mutex_lock(&app_thread_sig_mutex);
                    pthread_cond_signal(&app_thread_sig);
                    pthread_mutex_unlock(&app_thread_sig_mutex);
                } else {
                    printf ("[Recv thread]: Wrong DATA received\n");
                    // Discard the message. Waking up sending thread is necessary,
                    // If we don't do so, things following will happen:
                    // 1. client send a packet,
                    // 2. server received it and send back ack
                    // 3. ack packet is lost
                    // 4. client resend the packet
                    // 5. server discards the message since seq is wrong (but don't wake up sending thread)
                    // 6. client resend the packet
                    // 7. keep looping...
                    //
                    // In order to break the loop, whenever server receive an out of
                    // order packet, we wake up the send_thread to send the stored 
                    // ack.
                    pthread_mutex_lock(&send_thread_sig_mutex);
                    pthread_cond_signal(&send_thread_sig);
                    pthread_mutex_unlock(&send_thread_sig_mutex);
                } 
            } else if (type == 2 ) {
                //printf ("[Recv thread]: FIN received\n");
                // FIN packet received
                pthread_mutex_lock(&info_mutex);
                info.state = 2; // change state to 4-way handshake 
                pthread_mutex_unlock(&info_mutex);
                
                // Wake up send_thread to send FIN-ACK
                pthread_mutex_lock(&send_thread_sig_mutex);
                pthread_cond_signal(&send_thread_sig);
                pthread_mutex_unlock(&send_thread_sig_mutex);

                pthread_mutex_lock(&app_thread_sig_mutex);
                pthread_cond_signal(&app_thread_sig);
                pthread_mutex_unlock(&app_thread_sig_mutex);
            } else {
                fprintf(stderr, "Error: unexpected message type in receive thread, state 1\n");
            } 
        } else if (info.state == 2) {
            if (type == 4) {
                //printf ("[Recv thread]: 4-way handshake ACK received. I will break!\n");
                // ACK received 4-way handshake finished 


                pthread_mutex_lock(&info_mutex);
                info.state = 3; // change state to 4-way handshake 
                pthread_mutex_unlock(&info_mutex);

                // Wake the app thread and exit
                pthread_mutex_lock(&app_thread_sig_mutex);
                pthread_cond_signal(&app_thread_sig);
                pthread_mutex_unlock(&app_thread_sig_mutex);

                break;
            } else {
                fprintf(stderr, "Error: unexpected message type in receive thread, state 2\n");
            }  
        } else if (info.state == 3) {
            // state 3 is never reached since when in state 2 we will break
            fprintf(stderr, "Error: unexpected message type in receive thread, state 3\n");
            break;
        }
    } 
    return NULL;
}

// Send thread is only responsible for sending message according to the state
// It will not modify the state
// It can only be waken up by send thread and send one message each time
static void *send_thread(){
    while(1) {
        // In the begin of every iteration the send_thread will be blocked 
        // It is waken up by the send thread
        pthread_mutex_lock(&send_thread_sig_mutex);
        pthread_cond_wait(&send_thread_sig, &send_thread_sig_mutex);
        pthread_mutex_unlock(&send_thread_sig_mutex);
        //printf("[Send thread] in state %d~\n", info.state);
        // Reading info state is in the critical section
        // Other variables in info don't need to since they are almost read-only
        pthread_mutex_lock(&info_mutex);
        if (info.state == 0) {
            //printf("[Send thread] send SYN-ACK\n");
            // 3-way handshake period since no packet loss
            char msg[MAX_BUF_SIZE_MTCP];
            // encode_packet(SYN-ACK, info.ack_num, msg)
            unsigned int seq = htonl(info.ack_num);
            pthread_mutex_unlock(&info_mutex);
            memcpy(msg, &seq, 4);
            msg[0] = msg[0] | ((unsigned char)1 << 4);
            if (sendto(info.sock_fd, msg, 4, 0, \
                        (struct sockaddr*)(info.client_addr), info.addrlen) < 0) {
                fprintf(stderr, "send_to error\n");
                exit(1);
            } 
        } else if (info.state == 1) {
            //printf("[Send thread] send ACK with ack num %d\n", info.ack_num);
            // data transfering state send SYN + seq
            char msg[MAX_BUF_SIZE_MTCP];
            // encode_packet(ACK, info.ack_num, msg)
            unsigned int seq = htonl(info.ack_num);
            pthread_mutex_unlock(&info_mutex);
            memcpy(msg, &seq, 4);
            msg[0] = msg[0] | ((unsigned char)4 << 4);

            if (sendto(info.sock_fd, msg, 4, 0, 
                        (struct sockaddr*)(info.client_addr), info.addrlen) < 0) {
                fprintf(stderr, "send_to error\n");
                exit(1);
            } 
        } else if (info.state == 2) {
            // 4-way handshake state send FIN-ACK  and break the loop
            char msg[MAX_BUF_SIZE_MTCP];
            // encode_packet(FIN-ACK, info.ack_num, msg);
            unsigned int seq = htonl(++info.ack_num);
            //printf("[Send thread] send FIN-ACK with ack num %d\n", info.ack_num);
            pthread_mutex_unlock(&info_mutex);
            memcpy(msg, &seq, 4);
            msg[0] = msg[0] | ((unsigned char)3 << 4);
           
            if (sendto(info.sock_fd, msg, 4, 0, 
                        (struct sockaddr*)(info.client_addr), info.addrlen) < 0) {
                fprintf(stderr, "send_to error\n");
                exit(1);
            } 
            //printf("[Send thread] send FIN-ACK I exit!\n");
            // break the loop
            break;
        } else {
            pthread_mutex_unlock(&info_mutex);
            // do nothing to ignore the signal
            fprintf(stderr, "Error: send_thread in impossible state\n");
        } 
    } 
    return NULL;
}
