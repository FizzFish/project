#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

enum crash {
    NONE,
    TIMEOUT,
    CRASH,
    CRASH_OVF,
    CRASH_UAF
};

//verify whether poc will be crash
void verify(char* path, char** argv, int timeout)
{
    int pip[2];
    pipe(pip);
    pid_t pid = fork();
    if (!pid) {
        close(1);
        dup2(pip[1], 2);
        close(pip[0]);
        //close(2);
        execv(path, argv);
    }
    close(pip[1]);
    printf("argv = %s %s %s\n", argv[0], argv[1], argv[2]);
    int status;
    int cur_crash = NONE;

    sleep(timeout);
    if (!waitpid(pid, &status, WNOHANG))
        cur_crash = TIMEOUT;
    else if (WIFSIGNALED(status))
    {
        int kill_signal = WTERMSIG(status);
        cur_crash = CRASH;
        printf("child crash %d\n", kill_signal);
    }
    printf("status = %d\n", status);

    char errinfo[1025];
    while(read(pip[0], errinfo, 1024) > 0) {
        if(strstr(errinfo, "buffer-overflow"))
            cur_crash = CRASH_OVF;
        else if(strstr(errinfo, "heap-use-after-free"))
            cur_crash = CRASH_UAF;
        else
            break;
        memset(errinfo, 0, 1025);
    }
    printf("return is %d\n", cur_crash);

}

int main(int argc, char ** argv)
{
    verify("bsdtar", argv+1, 2);
    return 0;
}
