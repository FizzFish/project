#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <sched.h>
#include<stdio.h>
#include<stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <regex.h>
#include <string.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/time.h>
#include<sys/wait.h>
#include<fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include "queue.h"

/**
In proc.h, we wrap some functions to get the information from /proc/pid.
*/

typedef struct Argument Argument;

struct Argument
{
    char *name;
    int kind;//0=>name; 1=>@@
    QSIMPLEQ_ENTRY(Argument) node;
};


typedef struct Process
{
    int pid;
    char *elf_name;
    char *cwd;
    int fuzz_kind; //0: CANNOT; 1: FILEFUZZ; 2: PROFUZZ
    Argument* fuzz_arg;
    int argnum;
    int port[5];
    int portn;
    int listen_port;
    QSIMPLEQ_HEAD(, Argument) arglist;
    QSIMPLEQ_ENTRY(Process) next;
} Process;

typedef struct ProcList
{
    pthread_mutex_t mutex;// = PTHREAD_MUTEX_INITIALIZER;  
    pthread_cond_t  cond;//  = PTHREAD_COND_INITIALIZER;  
    int count;
    QSIMPLEQ_HEAD(, Process) list;
} ProcList;

typedef struct tcpEntry
{
    uint32_t raddr, rport;
    uint32_t laddr, lport;
    int state, inode;
    QSIMPLEQ_ENTRY(tcpEntry) next;
} tcpEntry;

typedef QSIMPLEQ_HEAD(TcpList, tcpEntry) TcpList;

typedef struct Fuzz
{
    char root[20];
    char in[20];
    char out[20];
    Process * proc;

} Fuzz;

bool is_elf(char*);
bool root_own(int);
bool has_file_in_arg(int);
bool is_listen(int);
char* get_abs_name(Process*);

Process* get_process(int);
void free_proc(Process*);
void extract_cmd(Process*);
bool filter(Process*);
int can_fuzz(Process*, TcpList*);
void show_fuzz_cmd(Process*);

void fuzz(Process * proc);
void prepare_env(Fuzz*);
void sniffer(Process*, int);
void procNet(void);

void core_pattern(void);
void cpu_performance(void);

extern FILE* logfp;




