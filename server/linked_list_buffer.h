#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct node {
    char message[1024];
    int msg_len;
    struct node* next;
} node_t; 

void print_list(node_t * head) {
    node_t * current = head;
    while(current != NULL) {
        current->message[current->msg_len] = '\0';
            printf("%s\n", current->message);
        current = current->next;
    } 
} 

void push_buffer(node_t* head, char* msg, int len) {
    node_t* current = head;
    while (current->next!= NULL) {
        current = current->next;
    } 
    current->next = (node_t *)malloc(sizeof(node_t));
    current->next->msg_len = len;
    memcpy(current->next->message, msg, len);
    current->next->next = NULL;
} 

int remove_first(node_t* head, unsigned char* buf) {
    if (head->next == NULL) {
        return 0;
    } 
    node_t* current = head->next;
    char* msg = current->message;
    memcpy(buf, msg, current->msg_len);
    int ret_len = current->msg_len;
    head->next = current->next;
    free(current);
    return ret_len;
} 

int num_of_buffer(node_t* head) {
    int count = 0;
    node_t* current = head;
    while (current->next !=NULL) {
        current = current->next;
        count ++;
    } 
    return count;
} 
