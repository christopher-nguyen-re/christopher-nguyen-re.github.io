// gcc ./linked.c -m32 -o linked -lpthread

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#define MAXTHREADS 2

typedef struct _Node {
    struct _Node* next;
    char* content;
} Node;

Node* head = NULL;

char task_data[MAXTHREADS][128];
pthread_t threads[MAXTHREADS];
char running[MAXTHREADS];

void printflag() {
    system("/bin/cat ./flag.txt");
}

void readline(char* buf, int n, FILE* in) {
    fgets(buf, n, in);
    buf[strcspn(buf, "\n")] = 0;
}

void *add_task(void* id) {
    int threadid = (int) id;
    char* data = task_data[threadid];
    printf("Thread %d: add %s\n",threadid,data);
    sleep(1);
    printf("Thread %d: add done\n",threadid);
    Node* n = malloc(sizeof(Node));
    n->content = strdup(data);
    n->next = head;
    head = n;
    running[threadid] = 0;
    return NULL;
}

void *delete_task(void* id) {
    int threadid = (int) id;
    char* data = task_data[threadid];
    int index = 0;
    if (!sscanf(data,"%d",&index)) {
        printf("Invalid index\n");
        return NULL;
    }
    printf("Thread %d: delete item %d\n",threadid,index);
    if (!head) {
        printf("Empty list\n");
        return NULL;
    }
    if (index < 0) {
        printf("Invalid index\n");
        return NULL;
    }
    if (!index) {
        Node* tmp = head->next;
        free(head);
        head = tmp;
    } else {
        index--;
        Node* prev = head;
        while (index > 0) {
            if (!prev) {
                printf("Invalid index\n");
                return NULL;
            }
            prev = prev->next;
            index--;
        }
        if (!prev || !prev->next) {
            printf("Invalid index\n");
            return NULL;
        }
        Node* next = prev->next->next;
        sleep(1);
        Node* cur = prev->next;
        prev->next = next;
        free(cur);
    }
    printf("Thread %d: delete done\n",threadid);
    running[threadid] = 0;
    return NULL;
}

void *update_task(void* id) {
    int threadid = (int) id;
    char* data = task_data[threadid];
    int index = 0;
    char new[128];
    if (sscanf(data,"%d;%s",&index,new) != 2) {
        return NULL;
    }
    printf("Thread %d: update item %d with %s\n",threadid,index,new);
    if (index < 0) {
        printf("Invalid index\n");
        return NULL;
    }
    Node* cur = head;
    while (index > 0) {
        if (!cur) {
            printf("Invalid index\n");
            return NULL;
        }
        cur = cur->next;
        index--;
    }
    if (!cur) {
        printf("Invalid index\n");
        return NULL;
    }
    sleep(1);
    if (strlen(new) > strlen(cur->content)) {
        free(cur->content);
        cur->content = strdup(new);
    } else {
        strcpy(cur->content,new);
    }
    printf("Thread %d: update done\n",threadid);
    running[threadid] = 0;
    NULL;
}

void addnode() {
    printf("Send the strings to add to the list, one on each line.\n");
    printf("When done, send an empty line.\n");
    char line[128];
    while (1) {
        readline(line, sizeof(line), stdin);
        if (!strlen(line)) {
            break;
        }
        int i = 0;
        while (1) {
            if (!running[i]) {
                running[i] = 1;
                strncpy(task_data[i], line, 128);
                pthread_create(&threads[i], NULL, add_task, (void*) i);
                break;
            }
            usleep(10000);
            i = (i+1) % MAXTHREADS;
        }
    }
}

void deletenode() {
    printf("Send the index of the item to delete, one on each line.\n");
    printf("When done, send an empty line.\n");
    char line[128];
    while (1) {
        readline(line, sizeof(line), stdin);
        if (!strlen(line)) {
            break;
        }
        int i = 0;
        while (1) {
            if (!running[i]) {
                running[i] = 1;
                strncpy(task_data[i], line, 128);
                pthread_create(&threads[i], NULL, delete_task, (void*) i);
                break;
            }
            usleep(10000);
            i = (i+1) % MAXTHREADS;
        }
    }
}

void updatenode() {
    printf("Send the index and new string in the format index;newString, one pair on each line.\n");
    printf("When done, send an empty line.\n");
    char line[128];
    while (1) {
        readline(line, sizeof(line), stdin);
        if (!strlen(line)) {
            break;
        }
        int i = 0;
        while (1) {
            if (!running[i]) {
                running[i] = 1;
                strncpy(task_data[i], line, 128);
                pthread_create(&threads[i], NULL, update_task, (void*) i);
                break;
            }
            usleep(10000);
            i = (i+1) % MAXTHREADS;
        }
    }
}

void printlist() {
    Node* cur = head;
    int i = 0;
    while (cur != NULL) {
        printf("Item %d: %s\n",i,cur->content);
        i++;
        cur = cur->next;
    }
}

int main(int argc, const char* argv[]) {
    setbuf(stdout, NULL);
    printf("Commands:\n"
           "\n"
           "add: Add an item to the beginning of the list.\n"
           "delete: Delete an item in the list.\n"
           "update: Update an item in the list.\n"
           "print: Print the list.\n"
           "exit: Exit.\n");
    char line[512];
    while (1) {
        printf("> ");
        readline(line, sizeof(line), stdin);
        if (!strcmp(line,"add")) {
            addnode();
        } else if (!strcmp(line,"delete")) {
            deletenode();
        } else if (!strcmp(line,"update")) {
            updatenode();
        } else if (!strcmp(line,"print")) {
            printlist();
        } else if (!strcmp(line,"exit")) {
            break;
        } else {
            printf("Invalid command.\n");
        }
    }
}
