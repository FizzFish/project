#include "proc.h"
#include "queue.h"

extern FILE* logfp;

inline char* get_abs_name(Process* proc)
{
    return strrchr(proc->elf_name, '/') + 1;
}

static bool in_white(Process* proc)
{
    char white_file[20] = "white";
    FILE *fp = fopen(white_file, "r");
    size_t size = 0;
    char *line = NULL;
    char *abs_name = get_abs_name(proc);
    while(getline(&line, &size, fp) != -1)
    {
        if (strncmp(abs_name, line, strlen(line)-1) == 0) {
            //printf("in white list, %s %s\n", abs_name, line);
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}

bool is_elf(char * elf_name)
{
    FILE *fp = fopen(elf_name, "r");
    if (fp == NULL)
        return false;
    char magic[5];
    fread(magic, 1, 4, fp);
    fclose(fp);
    if ((uint8_t)magic[0] == 0x7f && (uint8_t)magic[1] == 0x45 
        && (uint8_t)magic[2] == 0x4c && (uint8_t)magic[3] == 0x46)
        return true;
    return false;
}

bool root_own(int pid)
{
    char status_file[50];
    sprintf(status_file, "/proc/%d/status", pid);
    size_t size = 0;
    char *line = NULL;
    FILE *fp = fopen(status_file, "r");
    int uid = 0;
    char match[20];
    regmatch_t pmatch[2];
    const size_t nmatch = 2;
    if (!fp) {
        perror("open status failed");
        return true;
    }
    while(getline(&line, &size, fp) != -1)
    {
        if (strstr(line, "Uid:") != NULL) {
            regex_t reg;
            const char *pattern = "^Uid:.([0-9]+).+$";
            regcomp(&reg, pattern, REG_EXTENDED);
            int status = regexec(&reg, line, nmatch, pmatch, 0);
            if (status == REG_NOMATCH) {
                regfree(&reg);
                perror("No match");
                return true;
            } else {
                int len = pmatch[1].rm_eo - pmatch[1].rm_so;
                memcpy(match, line + pmatch[1].rm_so, len);
                match[len] = 0;
                uid = atoi(match);
            }
            regfree(&reg);
        }
    }
    if (uid == 0)
        return true;
    return false;
}

void show_fuzz_cmd(Process* proc)
{
    Argument *argp;
    fprintf(logfp, "fuzz cmd: %s ", proc->elf_name);
    QSIMPLEQ_FOREACH(argp, &proc->arglist, node)
    {
        if (argp->kind == 1)
            fprintf(logfp, " @@");
        else
            fprintf(logfp, " %s", argp->name);
    }
    fprintf(logfp, "\n");
    fflush(logfp);
}

bool is_file(Argument* arg, char* cwd)
{
    //check if arg is config file in /etc
    if (strncmp(arg->name, "/etc", 4) == 0) {
        return false;
    }
    if (strncmp(arg->name, "/proc", 5) == 0) {
        return false;
    }
    if (strncmp(arg->name, "/var", 4) == 0) {
        return false;
    }
    if (strncmp(arg->name, "/run", 4) == 0) {
        return false;
    }
    if (strncmp(arg->name, "/dev", 4) == 0) {
        return false;
    }
    if (strncmp(arg->name, "/sys", 4) == 0) {
        return false;
    }
    if (strncmp(arg->name, cwd, strlen(cwd)) == 0) { //absolute path
        if (!access(arg->name, 0)) {
            return true;
        }
    } else {
        char *real = malloc(strlen(arg->name) + strlen(cwd)+2);
        sprintf(real, "%s/%s", cwd, arg->name);
        if (!access(real, 0)) {
            free(arg->name);
            arg->name = real;
            return true;
        } else
            free(real);
    }
    // arg is not a file arg
    return false;
}

bool can_fuzz_file(Process* proc)
{
    Argument *argp;
    bool find = false;
    bool first = true;
    QSIMPLEQ_FOREACH(argp, &proc->arglist, node)
    {
        if(is_file(argp, proc->cwd)) {
            find = true;
            proc->fuzz_arg = argp;
            argp->kind = 1;
            break;
        }
    }
    if (find) {
        proc->fuzz_kind = 1;
        fprintf(logfp, "File fuzz %d, fuzz arg is %s\n", proc->pid, proc->fuzz_arg->name);
    }
    return find;
}

bool can_fuzz_protocol(Process* proc, TcpList* tcplist)
{
    char fd[50], file[300], real[50];
    struct dirent * pdir;
    int socknum = 0;
    tcpEntry *tcp;
    sprintf(fd, "/proc/%d/fd", proc->pid);
    DIR * fd_dir = opendir(fd);
    if (fd_dir < 0) {
        perror("opendir");
    }
    while((pdir = readdir(fd_dir)) != 0) {
        sprintf(file, "%s/%s", fd, pdir->d_name);
        if (readlink(file, real, 50) < 0)
            continue;
        if (strstr(real, "socket")) {
            socknum = atoi(real+8);
            QSIMPLEQ_FOREACH(tcp, tcplist, next)
                if (tcp->inode == socknum) {
                    if(tcp->rport == 27017) // it's mongod, pass
                        return false;
                    proc->port[proc->portn++] = tcp->rport;
                    proc->fuzz_kind = 2;
                }
        }
    }

    if (proc->portn)
        return true;
    return false;
}

// 0: CANNOT; 1: FILE; 2: PROTOCOL
int can_fuzz(Process* proc, TcpList* tcplist)
{
    if (in_white(proc)) {
        return 0;
    }
    if (!is_elf(proc->elf_name))
        return 0;
#if 0
    if (root_own(proc->pid))
        return 0;
#endif
    extract_cmd(proc);
    if (can_fuzz_file(proc))
        return 1;
    else if (can_fuzz_protocol(proc, tcplist))
        return 2;
}

static bool get_link(char* path, char** real)
{
    char link[1024];
    int len = readlink(path, link, 1024);
    if (len < 0)
        return false;
    link[len] = 0;
    *real = malloc(len+1);
    strcpy(*real, link);
    return true;
}

Process* get_process(int pid)
{
    Process *proc = malloc(sizeof(Process));
    memset(proc, 0, sizeof(Process));
    proc->pid = pid;
    QSIMPLEQ_INIT(&proc->arglist);

    char file_name[100];
    sprintf(file_name, "/proc/%d/exe", pid);
    if (!get_link(file_name, &proc->elf_name)) {
        free(proc);
        return NULL;
    }
    //printf("%s %s %s\n", proc->elf_name, proc->elf_name, proc->abs_name);

    // analysis /proc/pid/cwd
    sprintf(file_name, "/proc/%d/cwd", pid);
    if (!get_link(file_name, &proc->cwd)) {
        free(proc->elf_name);
        free(proc);
        return NULL;
    }
    return proc;
}

void extract_cmd(Process *proc)
{
    // analysis /proc/pid/cmdline
    char file_name[100];
    sprintf(file_name, "/proc/%d/cmdline", proc->pid);
    FILE* fp = fopen(file_name, "r");
    if (!fp)
        perror("fread");
    size_t size = 0;
    char *line = NULL;
    int c;
    char arg[10240], *p = arg;
    bool first = true;
    while((c = fgetc(fp)) != EOF)
    {
        *p++ = c;
        if (!c) {
            if (first) {
                first = false;
                proc->argnum = 1;
            } else {
                Argument *argument = malloc(sizeof(Argument));
                memset(argument, 0, sizeof(Argument));
                argument->name = malloc(strlen(arg)+1);
                strcpy(argument->name, arg);
                QSIMPLEQ_INSERT_TAIL(&proc->arglist, argument, node);
                proc->argnum++;
            }
            memset(arg, 0 , 1024);
            p = arg;
        }
    }
    fclose(fp);
}

static void safe_free(void *p)
{
    if (p)
        free(p);
}
void free_proc(Process * proc)
{
    Argument* argp;
    QSIMPLEQ_FOREACH(argp, &proc->arglist, node)
    {
        safe_free(argp->name);
        safe_free(argp);
    }
    safe_free(proc->elf_name);
    safe_free(proc->cwd);
    safe_free(proc);
}

