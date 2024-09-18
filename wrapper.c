#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <dirent.h>
#include <errno.h>

#define MAX_ARGS 1024

char* find_ld_linux(const char* lib_dir) {
    DIR* dir;
    struct dirent* entry;
    char* ld_linux = NULL;

    dir = opendir(lib_dir);
    if (dir == NULL) {
        perror("opendir");
        return NULL;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "ld-linux", 8) == 0 && strstr(entry->d_name, ".so") != NULL) {
            ld_linux = strdup(entry->d_name);
            break;
        }
    }

    closedir(dir);
    return ld_linux;
}

int main(int argc, char *argv[]) {
    char *dir, *parent_dir, *base_name;
    char lib_dir[PATH_MAX];
    char ld_path[PATH_MAX];
    char executable_path[PATH_MAX];
    char* ld_linux;
    char* new_argv[MAX_ARGS + 2];
    int i;
    size_t ret;

    dir = dirname(strdup(argv[0]));
    base_name = basename(strdup(argv[0]));
    parent_dir = dirname(strdup(dir));

    ret = (size_t)snprintf(lib_dir, sizeof(lib_dir), "%s/lib", parent_dir);
    if (ret >= sizeof(lib_dir)) {
        fprintf(stderr, "Error: lib_dir path too long\n");
        return 1;
    }

    ld_linux = find_ld_linux(lib_dir);
    if (ld_linux == NULL) {
        fprintf(stderr, "Could not find ld-linux in %s\n", lib_dir);
        return 1;
    }

    ret = (size_t)snprintf(ld_path, sizeof(ld_path), "%s/%s", lib_dir, ld_linux);
    if (ret >= sizeof(ld_path)) {
        fprintf(stderr, "Error: ld_path too long\n");
        free(ld_linux);
        return 1;
    }
    free(ld_linux);

    ret = (size_t)snprintf(executable_path, sizeof(executable_path), "%s/.%s", dir, base_name);
    if (ret >= sizeof(executable_path)) {
        fprintf(stderr, "Error: executable_path too long\n");
        return 1;
    }

    if (access(executable_path, F_OK) == -1) {
        fprintf(stderr, "Real executable not found: %s\n", executable_path);
        return 1;
    }

    new_argv[0] = ld_path;
    new_argv[1] = executable_path;
    for (i = 1; i < argc && i < MAX_ARGS; i++) {
        new_argv[i + 1] = argv[i];
    }
    new_argv[i + 1] = NULL;

    execv(ld_path, new_argv);

    perror("execv");
    return 1;
}
