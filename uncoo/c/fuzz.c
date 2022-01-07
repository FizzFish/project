#include "proc.h"

TcpList tcplist;

static void prepare_fuzz(Fuzz *fuzz, Process * proc)
{
    char cmd[100];
    sprintf(fuzz->root, "env/%d", proc->pid);
    sprintf(fuzz->in, "%s/in", fuzz->root);
    sprintf(fuzz->out, "%s/out", fuzz->root);
    fuzz->proc = proc;

#if 1
    sprintf(cmd, "./cobot.sh %s > /dev/null 2>&1\n", fuzz->root);
    printf("debug: %s\n", cmd);
    system(cmd);
#endif
    
    prepare_env(fuzz);
    //show_fuzz_cmd(proc);

    int pid, status;
    if (proc->fuzz_kind == 2) {
        char pcap[250];
        sprintf(pcap, "%s/pcap", fuzz->in);
        int infd = open(pcap, O_WRONLY | O_CREAT, S_IRWXU | S_IROTH);
        if (infd < 0)
            perror("open");
        /**
        pid = fork();
        if (pid < 0)
            perror("fork");
        if (!pid) {
            sniffer(proc, infd);
        }
        waitpid(pid, &status, 0);
        //printf("status is %d\n", status);
        */
        sniffer(proc, infd);
    }
}

static int fuzz_pid;
static void handle_timeout(int sig) {
    fprintf(logfp, "timeout kill %d\n", fuzz_pid);
    kill(fuzz_pid, SIGINT);
}

void fuzz(Process * proc)
{
    Fuzz fuzz;
    prepare_fuzz(&fuzz, proc);

    int pid = fork();
    if (pid < 0)
        perror("fork");
    if (!pid) {
        //while(1);
        Argument* argp;
        int argnum = proc->argnum;
        char ** argv, **basearg;
        int i = 0, basenum = 8;
        if (proc->fuzz_kind == 1) {
            //bin/afl-fuzz -i in -o out -Q -m none
            char *fuzz_arg[] = {"./afl-fuzz", "-i", fuzz.in, "-o", fuzz.out,
                "-Q", "-m", "none"};
            basearg = fuzz_arg;
        } else {
        /**
            ./afl-fuzz -Q -d -i in -o out \
            -N tcp://127.0.0.1/8554 \
            -x rtsp.dict \
            -P RTSP -D 10000 -q 3 -s 3 -E -K -R \
            ./testOnDemandRTSPServer 8554
        */
            char *proto = "RTSP";// need to configure
            char server[100] = {0};
            sprintf(server, "tcp://127.0.0.1/%d", proc->listen_port);
            char *fuzz_arg[] = {"./afl-fuzz", "-i", fuzz.in, "-o", fuzz.out,
                "-Q", "-m", "none", "-d",
                "-N", server,
                "-P",  proto, "-D", "10000", "-q", "3", "-s", "3", "-E", "-K", "-R"};
            basearg = fuzz_arg;
            basenum = 22;
        }

        argnum += basenum+1;
        i = basenum;
        argv = malloc(argnum * sizeof(char*));
        memcpy(argv, basearg, basenum * sizeof(char*));

        argv[i] = malloc(strlen(proc->elf_name)+1);
        strcpy(argv[i], proc->elf_name);
        i++;
        QSIMPLEQ_FOREACH(argp, &proc->arglist, node)
        {
            if (!argp->kind) {
                argv[i] = malloc(sizeof(argp->name)+1);
                strcpy(argv[i], argp->name);
            } else {
                argv[i] = "@@";
            }
            i++;
        }
        argv[i] = NULL;
#if 1
        for(i=0;i<argnum;i++)
            if(argv[i]) {
                fprintf(logfp, "%s ", argv[i]);
            }
        fprintf(logfp, "\n");
#endif
    //    close(1);
        int fd = open("/var/run/netns/net1", O_RDONLY);
        setns(fd, CLONE_NEWNET);
        close(fd);
        fprintf(logfp, "Now fuzz process in new net namespace\n");
        system("ip addr");
        execv("afl-fuzz", argv);
    }

    fuzz_pid = pid;
    int status;
    signal(SIGALRM, handle_timeout);
#if 0
    struct itimerval it;
    it.it_value.tv_sec = 5;
    it.it_value.tv_usec = 0;
    it.it_interval.tv_sec = 1;
    it.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &it, NULL);
#endif
    alarm(150);
    waitpid(fuzz_pid, &status, 0);
    fprintf(logfp, "fuzz end, status=%d\n", status);

}

static int getval(char* line, regmatch_t *pmatch, int index, int base)
{
    char match[50];
    int len = pmatch[index].rm_eo - pmatch[index].rm_so;
    char *end;
    memcpy(match, line + pmatch[index].rm_so, len);
    match[len] = 0;
    return (int)strtol(match, &end, base);
}

void procNet() {
    char path[50] = "/proc/net/tcp";
    size_t size = 0;
    char *line = NULL;
    char match[50];
    regmatch_t pmatch[10];
    size_t nmatch = 10; 
    //0: 00000000:AE0F 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 29467 1 0000000000000000 100 0 0 10 0
    const char *pattern = "^\\s*([0-9]+): ([0-9A-F]+):(....) ([0-9A-F]+):(....) (..) ([^ ]+ ){3}\\s*([0-9]+)\\s+[0-9]+\\s+([0-9]+).*$";
    regex_t reg;
    regcomp(&reg, pattern, REG_EXTENDED);
    FILE *fp = fopen(path, "r");
    bool first = true;
    QSIMPLEQ_INIT(&tcplist);
    while(getline(&line, &size, fp) != -1)
    {
        if (first) {
            first = false;
            continue;
        }
        //puts(line);
        int status = regexec(&reg, line, nmatch, pmatch, 0);
        if (status != REG_NOMATCH) {
            tcpEntry *tcp = malloc(sizeof(tcpEntry));
            tcp->raddr = getval(line, pmatch, 2, 16);
            tcp->rport =  getval(line, pmatch, 3, 16);
            tcp->laddr = getval(line, pmatch, 4, 16);
            tcp->lport =  getval(line, pmatch, 5, 16);
            tcp->state = getval(line, pmatch, 6, 16);
            tcp->inode = getval(line, pmatch, 9, 10);
            QSIMPLEQ_INSERT_TAIL(&tcplist, tcp, next);
            //printf("extract %d:%d %d:%d %d %d\n", ra, rp, la, lp, state, inode);
        }
            
    }
    regfree(&reg);
}
