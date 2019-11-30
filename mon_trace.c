#define _GNU_SOURCE
#include "mon_trace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <libunwind.h>
#include <libunwind-ptrace.h>

typedef struct TRACEE {
    pthread_t thread_id;
    pid_t pid;
} TRACEE;

static void showBacktrace(unw_addr_space_t space, void *target) {
    
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

static void childStopped(pid_t pid, int status,
                         unw_addr_space_t space, void *target)
{
    int signum;

    signum = WSTOPSIG(status);

    if (signum == SIGTRAP) {
        if (status >> 8 == (SIGTRAP | PTRACE_EVENT_EXIT << 8)) {
            int exitStatus;
            ptrace(PTRACE_GETEVENTMSG, pid, NULL, &exitStatus);
            printf("child exit(%d)\n", exitStatus);

            showBacktrace(space, target);
        }
        // group stop, syscall stop, ptrace events
    } else if (signum == SIGSEGV) {

    }
}

static int Mon_TracerSetInitOptions(pid_t pid)
{
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEEXIT) == -1) {
        perror("set tracee O_TRACEEXIT option");
        return -1;
    }

    return 0;
}

static int Mon_TracerAttach(pid_t pid)
{
    int status;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace child");
        return -1;
    }

    if (waitpid(pid, &status, __WALL) == -1) {
        perror("waitpid for first attach");
        return -1;
    }

    if (WIFEXITED(status)) {
        return -1;

    } else if (WIFSIGNALED(status)) {
        return -1;

    } else if (WIFSTOPPED(status)) {
        if (Mon_TracerSetInitOptions(pid) != 0) {
            return -1;
        }

    } else {
        return -1;
    }

    return 0;
}

static void Mon_TracerWatch(TRACEE *tracee)
{
    unw_addr_space_t space = unw_create_addr_space(&_UPT_accessors, __LITTLE_ENDIAN);
    void *target = _UPT_create(tracee->pid);
    
    int status;
    do {
        if (waitpid(tracee->pid, &status, __WALL) == -1) {
            perror("waitpid");
            break;
        }

        if (WIFEXITED(status)) {
            printf("exited, status=%d\n", WEXITSTATUS(status));

        } else if (WIFSIGNALED(status)) {
            printf("killed by signal %d\n", WTERMSIG(status));

        } else if (WIFSTOPPED(status)) {
            childStopped(tracee->pid, status, space, target);

            ptrace(PTRACE_CONT, tracee->pid, NULL, NULL);
        } else if (WIFCONTINUED(status)) {
            printf("continued\n");
        }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));

    _UPT_destroy(target);
}

static void *Mon_TracerMain(void *arg)
{
    TRACEE *tracee = (TRACEE *)arg;
    
    if (Mon_TracerAttach(tracee->pid) != 0) {
        return "attach faild";
    }

    Mon_TracerWatch(tracee);

    return "exit";
}

int Mon_TracerStart(pid_t child)
{
    pthread_attr_t attr;
    TRACEE *tracee;

    tracee = (TRACEE *)malloc(sizeof(TRACEE));
    if (tracee == NULL) {
        return -1;
    }
    tracee->pid = child;

    if (pthread_attr_init(&attr) != 0) {
        perror("tracer thread attr initialization");
        free(tracee);
        return -1;
    }

    if (pthread_create(&tracee->thread_id, &attr, &Mon_TracerMain, tracee) != 0) {
        perror("tracer thread creation");
        free(tracee);
        pthread_attr_destroy(&attr);
        return -1;
    }

    return 0;
}

