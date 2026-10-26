#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define TRUSTED_ROOT "/Library/Application Support/CobaltEarlyResetTest"
#define TRUSTED_SCRIPT TRUSTED_ROOT "/capture-early-reset.sh"
#define TRUSTED_PATH "/usr/bin:/bin:/usr/sbin:/sbin"

static volatile sig_atomic_t child_pid = -1;
static volatile sig_atomic_t pending_signal = 0;

static void
forward_signal(int signo)
{
    pid_t pid = (pid_t)child_pid;

    if (pid > 0) {
        (void)kill(pid, signo);
    } else {
        pending_signal = signo;
    }
}

static int
valid_fixed_file(const char *path, int is_directory)
{
    struct stat st;

    if (lstat(path, &st) != 0 || S_ISLNK(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return 0;
    }
    if (is_directory) {
        return S_ISDIR(st.st_mode);
    }
    return S_ISREG(st.st_mode);
}

static int
check_trusted_installation(void)
{
    if (geteuid() != 0) {
        (void)fprintf(stderr, "capture launcher requires effective UID 0\n");
        return 0;
    }
    if (!valid_fixed_file(TRUSTED_ROOT, 1) ||
        !valid_fixed_file(TRUSTED_SCRIPT, 0)) {
        (void)fprintf(stderr,
                      "trusted capture directory or script is missing or unsafe\n");
        return 0;
    }
    return 1;
}

static int
run_agent(const char *mode)
{
    struct sigaction action;
    const char *script_arg;
    pid_t pid;
    int status;
    int signo;

    script_arg = strcmp(mode, "--run-agent") == 0 ? "--capture-once" : "--probe-usb";
    if (setenv("PATH", TRUSTED_PATH, 1) != 0) {
        (void)perror("setenv PATH");
        return 1;
    }
    if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) {
        (void)perror("signal SIGCHLD");
        return 1;
    }
    (void)memset(&action, 0, sizeof(action));
    action.sa_handler = forward_signal;
    (void)sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) != 0 ||
        sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGHUP, &action, NULL) != 0) {
        (void)perror("sigaction");
        return 1;
    }

    pid = fork();
    if (pid < 0) {
        (void)perror("fork");
        return 1;
    }
    if (pid == 0) {
        (void)signal(SIGTERM, SIG_DFL);
        (void)signal(SIGINT, SIG_DFL);
        (void)signal(SIGHUP, SIG_DFL);
        execl("/bin/sh", "sh", TRUSTED_SCRIPT, script_arg, (char *)NULL);
        (void)perror("exec /bin/sh");
        _exit(127);
    }

    child_pid = (sig_atomic_t)pid;
    signo = (int)pending_signal;
    if (signo != 0) {
        (void)kill(pid, signo);
    }

    for (;;) {
        if (waitpid(pid, &status, 0) >= 0) {
            break;
        }
        if (errno != EINTR) {
            (void)perror("waitpid");
            child_pid = -1;
            return 1;
        }
    }
    child_pid = -1;

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 1;
}

static void
usage(FILE *stream)
{
    (void)fprintf(stream,
                  "Usage: CobaltEarlyCapture --help\n"
                  "       CobaltEarlyCapture --run-agent\n"
                  "       CobaltEarlyCapture --probe-agent\n");
}

int
main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        usage(stdout);
        return 0;
    }
    if (argc != 2 ||
        (strcmp(argv[1], "--run-agent") != 0 &&
         strcmp(argv[1], "--probe-agent") != 0)) {
        usage(stderr);
        return 2;
    }
    if (!check_trusted_installation()) {
        return 1;
    }
    return run_agent(argv[1]);
}
