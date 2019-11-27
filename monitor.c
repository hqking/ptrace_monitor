#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <endian.h>
#include <libunwind.h>
#include <libunwind-ptrace.h>

static void usage(const char *self)
{
    printf("%s program [arguments]\n", self);
}

void show_backtrace(unw_addr_space_t space, void *target) {
    
    unw_word_t ip, sp;
    char funcname[128];
    unw_word_t offset;
    unw_cursor_t cursor;
    unw_init_remote(&cursor, space, target);
    
    while (unw_step(&cursor) > 0) {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        unw_get_reg(&cursor, UNW_REG_SP, &sp);
        unw_get_proc_name(&cursor, funcname, sizeof(funcname), &offset);

        printf ("ip = %lx, sp = %lx %s(+%lu)\n", (long) ip, (long) sp, funcname, offset);
    }
}

static void childStopped(int status)
{
    int signum;

    signum = WSTOPSIG(status);

    printf("stopped by signal %d(%s)\n", signum, strsignal(signum));
}

static void traceChild(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace child");
    }

    unw_addr_space_t space = unw_create_addr_space(&_UPT_accessors, __LITTLE_ENDIAN);
    void *target = _UPT_create(pid);
    
    int status;
    do {
        if (waitpid(pid, &status, __WALL) == -1) {
            perror("waitpid");
            break;
        }

        if (WIFEXITED(status)) {
            printf("exited, status=%d\n", WEXITSTATUS(status));
            _UPT_destroy(target);
        } else if (WIFSIGNALED(status)) {
            printf("killed by signal %d\n", WTERMSIG(status));
            _UPT_destroy(target);
        } else if (WIFSTOPPED(status)) {
            childStopped(status);
            show_backtrace(space, target); 

            ptrace(PTRACE_CONT, pid, NULL, NULL);
        } else if (WIFCONTINUED(status)) {
            printf("continued\n");
        }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));
}

int main(int argc, char *argv[])
{
    pid_t pid;

    if (argc < 2) {
        usage(argv[0]);
        exit(0);
    }

    pid = fork();
    if (pid == 0) {
        if (execvp(argv[1], &argv[1]) == -1) {
            perror("execvp new program");
        }
    } else if (pid > 0) {
        traceChild(pid);        
    }
}
