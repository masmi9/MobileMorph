#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);

    printf("Attempting to attach to PID %d...\n", target_pid);

    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
        perror("ptrace attach failed");
        return 1;
    }

    waitpid(target_pid, NULL, 0);  // Wait for stop signal

    printf("Successfully attached to process %d. (Now detaching...)\n", target_pid);

    if (ptrace(PTRACE_DETACH, target_pid, NULL, NULL) == -1) {
        perror("ptrace detach failed");
        return 1;
    }

    printf("Detached.\n");
    return 0;
}
