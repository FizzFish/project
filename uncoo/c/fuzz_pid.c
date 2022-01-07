#include "proc.h"
extern TcpList tcplist;
FILE *logfp;
int main(int argc, char ** argv)
{
    int pid = atoi(argv[1]);
    logfp = stdout;
    procNet();
    Process *proc = get_process(pid);
    if (can_fuzz(proc, &tcplist)) {
        printf("fuzz %d\n", pid);
        fuzz(proc);
        free_proc(proc);
    }
    return 0;
}
