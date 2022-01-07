#include "proc.h"
#include <sys/wait.h>
#include <pthread.h>

FILE* logfp;

extern TcpList tcplist;
ProcList proclist;

static void handle_cancle(int sig) {
    fclose(logfp);
    exit(0);
}

void push_proc(Process* proc)
{
    QSIMPLEQ_INSERT_TAIL(&proclist.list, proc, next);
}

Process* pop_proc()
{
    Process* ret = QSIMPLEQ_FIRST(&proclist.list);
    QSIMPLEQ_REMOVE_HEAD(&proclist.list, next);
    return ret;
}

void search_process() {
    DIR * proc_dir = opendir("/proc");
    struct dirent * pdir;
    char status_file[300];//like /proc/100/status
    int pid;
    char path[100];
    Process *proc = NULL; 
    bool find = false;
    while((pdir = readdir(proc_dir)) != 0) {
        //if inode == 0, continue
        if (pdir->d_ino == 0)
            continue;
        if(pdir->d_name[0] < '0' || pdir->d_name[0] > '9')
            continue;
        pid = atoi(pdir->d_name);
        proc = get_process(pid);
        if (!proc) {
            continue;
        }
        if (can_fuzz(proc, &tcplist)) {
            printf("enter search process\n");
            pthread_mutex_lock(&proclist.mutex);  
            proclist.count++;  
            push_proc(proc);
            printf("----increment:%d.\n", proclist.count);  
            if (proclist.count != 0)  
                pthread_cond_signal(&proclist.cond);  
            pthread_mutex_unlock(&proclist.mutex);  
            printf("out search process\n");
        } else
            free_proc(proc);
    }

    if (!find)
        printf("Not find Process\n");
}

void fuzz_wait(void *arg)
{
    Process* proc;
    while(true) {
        printf("enter fuzz_wait\n");
        pthread_mutex_lock(&proclist.mutex);  
        if (proclist.count == 0)  
            pthread_cond_wait(&proclist.cond, &proclist.mutex);  
        proclist.count--;  
        printf("----decrement:%d.\n", proclist.count);  
        proc = pop_proc();
        fuzz(proc);
        pthread_mutex_unlock(&proclist.mutex);  
        printf("out fuzz_wait\n");
    }
}

void init_proc_list()
{
    pthread_mutex_init(&proclist.mutex, NULL);
    pthread_cond_init(&proclist.cond, NULL);
    QSIMPLEQ_INIT(&proclist.list);
}

void destroy_proc_list()
{
    pthread_mutex_destroy(&proclist.mutex);  
    pthread_cond_destroy(&proclist.cond);  
}

int main() {
    signal(SIGINT,handle_cancle);
    core_pattern();
    cpu_performance();
#if 0
    logfp = fopen("log", "w");
#else
    logfp = stdout;
#endif
    procNet();
    signal(SIGINT,handle_cancle);

    init_proc_list();
    pthread_t search_th, fuzz_th;  
    pthread_create(&search_th, NULL, (void*)search_process, NULL);  
    pthread_create(&fuzz_th, NULL, (void*)fuzz_wait, NULL);  
    pthread_join(search_th, NULL);  
    pthread_join(fuzz_th, NULL);  
    destroy_proc_list();
/**
    while(1) {
        search_process();
        fprintf(logfp, "sleeping 30 seconds.....\n");
        sleep(30);
    }
*/
    fclose(logfp);
    return 0;
}
