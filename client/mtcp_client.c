#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include "mtcp_client.h"

/* -------------------- Constant -------------------- */
// state
#define SYN 0
#define DATA 1
#define FIN 2
// receive status
// 0 for NULL
#define RECV_NULL 0
#define RECV_SYN_ACK 1
#define RECV_FIN_ACK 2
#define RECV_ACK 3
// max size of each packet
#define P_SIZE 1004
#define D_SIZE 1000
// Types in header
#define TP_SYN 0
#define TP_SYN_ACK 1
#define TP_FIN 2
#define TP_FIN_ACK 3
#define TP_ACK 4
#define TP_DATA 5
/* -------------------- Global Variables -------------------- */
typedef struct {
    unsigned int seq;
    unsigned char mode;
} Tuple;
static int state;  // mutex is not needed, since only app will change it.
static int substate = -1;
typedef struct _node
{
  char data[D_SIZE];
  int size;
  struct _node* next;
} mtcp_queue;
static mtcp_queue* head; // head of the queue, pop
static mtcp_queue* tail; // tail of the queue, push
// mtcp buffer is a queue, implemented as a linked list.
// additional mutex is not need, since sender sig will cover
/**
*  sender will not send the data in tail, unless FIN is read
*  when (head==tail OR head==NULL) AND not FIN AND not SYN, sender will always be blocked, which makes
*  it safe
*/
static int last_receive = RECV_NULL;
static unsigned char last_send[P_SIZE];
static int last_len;
static struct timespec ts;
static unsigned int seq = 0;  // sequence number
static unsigned int ack = 0;
static int skt_fd;
static struct sockaddr_in *sv_addr;
/* ThreadID for Sending Thread and Receiving Thread */
static pthread_t send_thread_pid;
static pthread_t recv_thread_pid;

static pthread_cond_t app_thread_sig = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t app_thread_sig_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_cond_t send_thread_sig = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t send_thread_sig_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t info_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Functions */
static void encode(unsigned char*, unsigned int, unsigned char);
static Tuple decode(unsigned char*, unsigned int, unsigned char);
static void *send_thread();
static void *receive_thread();
/* Connect Function Call (mtcp Version) */
void mtcp_connect(int socket_fd, struct sockaddr_in *server_addr){
/**
* change state to SYN
* create sender & receiver Thread
* signal sending Thread
* cond wait until sender signal
* change state to non-write
*/
  // remember addr
  skt_fd = socket_fd;
  sv_addr = (struct sockaddr_in *) malloc(sizeof(*server_addr));
  memcpy(sv_addr, server_addr, sizeof(*server_addr));
  // UDP connect
  // Create threads
  pthread_create(&send_thread_pid, NULL, send_thread, NULL);
  pthread_create(&recv_thread_pid, NULL, receive_thread, NULL);
  sleep(1);
  // change state
  state = SYN;  substate = 0;
  // signal sender
  pthread_mutex_lock(&send_thread_sig_mutex);
  pthread_cond_signal(&send_thread_sig);
  pthread_mutex_unlock(&send_thread_sig_mutex);
  // cond wait until sender signals
  // after signal, must satisfy condition, thus while is not need
  pthread_mutex_lock(&app_thread_sig_mutex);
  pthread_cond_wait(&app_thread_sig, &app_thread_sig_mutex);
  pthread_mutex_unlock(&app_thread_sig_mutex);
  // change state
  state = DATA;
}

/* Write Function Call (mtcp Version) */
int mtcp_write(int socket_fd, unsigned char *buf, int buf_len){
/**
* write data to mtcp queue
* (need to add mutex on tail node to avoid send while adding)
* signal sender
* return -1:  sendto return -1??
* mtcp_write after mtcp_close
*/
  if (state == FIN) return -1;
  // init if queue not constructed yet
  if (buf_len == 0) return 0;
  // no need to create new node or signal sender
  if (!tail)
  {
    tail = (mtcp_queue*) malloc(sizeof(mtcp_queue));
    tail->size = 0; tail->next = NULL; head = tail;
  }
  else if (head == tail) // to make sender block shorter time, move to the next node of tail
  {
    tail->next = (mtcp_queue*) malloc(sizeof(mtcp_queue));
    tail = tail->next; tail->size = 0; tail->next = NULL;
    // signal sender that the previous tail can be sent
    pthread_mutex_lock(&send_thread_sig_mutex);
    pthread_cond_signal(&send_thread_sig);
    pthread_mutex_unlock(&send_thread_sig_mutex);
  }
  // write data to mtcp queue tail
  int avail; //available size
  int ans = buf_len;
  while (buf_len > 0)
  {
    avail = D_SIZE - tail->size; // available size
    if (buf_len <= avail)  // enough to put all
    {
      memcpy(tail->data+tail->size, buf, buf_len);
      tail->size += buf_len; buf_len = 0;  // update size
    }
    else  // not enough, have to create new node
    {
      memcpy(tail->data+tail->size, buf, avail);  // cpy to tail
      tail->size = D_SIZE;  //update size
      buf += avail;  // next position of buf
      buf_len -= avail;  // update buf_len
      // create new node after tail
      tail->next = (mtcp_queue*) malloc(sizeof(mtcp_queue));
      tail = tail->next;  tail->size = 0; tail->next = NULL;
      // signal sender that the previous tail can be sent
      pthread_mutex_lock(&send_thread_sig_mutex);
      pthread_cond_signal(&send_thread_sig);
      pthread_mutex_unlock(&send_thread_sig_mutex);
    }
  }
  // signal sender
  pthread_mutex_lock(&send_thread_sig_mutex);
  pthread_cond_signal(&send_thread_sig);
  pthread_mutex_unlock(&send_thread_sig_mutex);
  return ans;
}

/* Close Function Call (mtcp Version) */
void mtcp_close(int socket_fd){
/**
* if connection closed then does nothing
* change state to FIN state
* cond wait until sender receiver are terminated (join)
* release memory, close UDP socket
*/
  // if connection closed then does nothing
  if (state == FIN) return;
  // change state
  state = FIN; substate = 0;
  // cond wait until sender receiver are terminated (join)
  // signal sender
  pthread_mutex_lock(&send_thread_sig_mutex);
  pthread_cond_signal(&send_thread_sig);
  pthread_mutex_unlock(&send_thread_sig_mutex);
  pthread_join(send_thread_pid, NULL);
  pthread_join(recv_thread_pid, NULL);
  // release memory, close UDP socket
  mtcp_queue *tmp = head;
  while (head)
  {
    tmp = head->next; free(head); head = tmp;
  }
  free(sv_addr);
  close(socket_fd);
}

static void *send_thread(){
  while (1)
  {
    // cond wait forever
    pthread_mutex_lock(&send_thread_sig_mutex);
    while ((head == NULL || head == tail) && state != SYN && state != FIN)
    {
      pthread_cond_wait(&send_thread_sig, &send_thread_sig_mutex);
    }
    pthread_mutex_unlock(&send_thread_sig_mutex);
    switch (state)
    {
      case SYN:
        // if last_receive == null
        if (last_receive == RECV_NULL && substate == 0)
        {
          // send SYN
          memset(last_send, 0, sizeof(last_send));
          encode(last_send, seq++, TP_SYN); last_len = 4;
          sendto(skt_fd, last_send, 4, 0, (struct sockaddr *) sv_addr, sizeof(*sv_addr));
          substate = 1;
          continue;
        }
        else if (last_receive == RECV_SYN_ACK && substate == 1)
        {
          last_receive = RECV_NULL;  // already handled
          // send ACK
          memset(last_send, 0, sizeof(last_send));
          encode(last_send, seq, TP_ACK); last_len = 4;
          sendto(skt_fd, last_send, 4, 0, (struct sockaddr *) sv_addr, sizeof(*sv_addr));
          substate = -1;
          pthread_mutex_lock(&app_thread_sig_mutex);
          pthread_cond_signal(&app_thread_sig);
          pthread_mutex_unlock(&app_thread_sig_mutex);
          continue;
        }
        else
        { 
          last_receive = RECV_NULL;
          continue;  // redundant
        }
        break;
      case FIN:
        if (last_receive != RECV_FIN_ACK && substate == 0)
        {
          last_receive = RECV_NULL;  // already handled;
          // send FIN and DATA
          memset(last_send, 0, sizeof(last_send));
          if (head != NULL) // more to send
          {
            // normal send
            memcpy(last_send+4, head->data, head->size);  // cpy the data
            encode(last_send, seq, TP_DATA);  seq += head->size;  //encode the header
            last_len = head->size+4;
            sendto(skt_fd, last_send, last_len, 0, (struct sockaddr *) sv_addr, sizeof(*sv_addr));
            // remove head
            mtcp_queue *tmp = head; head = head->next;  free(tmp);
            break;  // break the switch clause
          }
          else // no data remains
          {
            encode(last_send, seq++, TP_FIN); last_len = 4;
            substate = 1;
            sendto(skt_fd, last_send, last_len, 0, (struct sockaddr *) sv_addr, sizeof(*sv_addr));
            continue; // next loop
          }
        }
        else if (last_receive == RECV_FIN_ACK && substate == 1)
        {
          last_receive = RECV_NULL;  // already handled
          // send ACK
          memset(last_send, 0, sizeof(last_send));
          encode(last_send, seq, TP_ACK); last_len = 4;
          sendto(skt_fd, last_send, last_len, 0, (struct sockaddr *) sv_addr, sizeof(*sv_addr)); substate = -1;
          pthread_exit(NULL);
        }
        else  // redundant
        {
          last_receive = RECV_NULL;
          continue;
        }
        break;
      default:  // TRANSFER state
        // send head->data
        last_receive = RECV_NULL;
        memset(last_send, 0, sizeof(last_send));
        memcpy(last_send+4, head->data, head->size);  //cpy the data
        encode(last_send, seq, TP_DATA);  seq += head->size;  //encode the header
        last_len = head->size+4;
        sendto(skt_fd, last_send, last_len, 0, (struct sockaddr *) sv_addr, sizeof(*sv_addr));
        mtcp_queue* tmp = head; head = head->next; free(tmp); // remove head
        break;
    }
    // wait and resend
    pthread_mutex_lock(&send_thread_sig_mutex);
    clock_gettime(CLOCK_REALTIME, &ts); ts.tv_sec += 1;
    // seq: next to send
    while (ack < seq)
    {
      pthread_cond_timedwait(&send_thread_sig, &send_thread_sig_mutex, &ts);
      if (ack < seq)
      {
        // resend
        sendto(skt_fd, last_send, last_len, 0, (struct sockaddr *) sv_addr, sizeof(*sv_addr));
        clock_gettime(CLOCK_REALTIME, &ts); ts.tv_sec += 1;
      }
    }
    pthread_mutex_unlock(&send_thread_sig_mutex);
  }
}

static void *receive_thread(){
/**
* do the following forever:
* last-receive = receive from server
* signal sender
* if FIN and last-receive is FIN-ACK
*/
  unsigned char rcv_buf[P_SIZE];
  Tuple info;
  while (1)
  {
    // receive from server;
    recvfrom(skt_fd, rcv_buf, P_SIZE, 0, (struct sockaddr *) sv_addr, NULL);
    info = decode(rcv_buf, info.seq, info.mode);
    ack = info.seq;
    // if SYN_ACK THEN
    if (info.mode == TP_SYN_ACK)
      last_receive = RECV_SYN_ACK;
    // if FIN_ACK then
    if (info.mode == TP_FIN_ACK)
      last_receive = RECV_FIN_ACK;
    // if ACK then
    if (info.mode == TP_ACK)
      last_receive = RECV_ACK;
    // signal sender
    pthread_mutex_lock(&send_thread_sig_mutex);
    pthread_cond_signal(&send_thread_sig);
    pthread_mutex_unlock(&send_thread_sig_mutex);
    if (state == FIN && last_receive == RECV_FIN_ACK)
      pthread_exit(NULL);
  }
}

static void encode(unsigned char* buffer, unsigned int seq, unsigned char mode){
    //pdf shows that it should be htol instead of htonl, but I can not find the header file for htol.
    seq = htonl(seq);
    memcpy(buffer, &seq, 4);
    buffer[0] = buffer[0] | (mode << 4);
}

static Tuple decode(unsigned char* buffer, unsigned int seq, unsigned char mode){
    mode = buffer[0]>>4;
    buffer[0] = buffer[0] & 0x0F;
    memcpy(&seq, buffer, 4);
    seq = ntohl(seq);
    Tuple result = {seq, mode};
    return result;
}
