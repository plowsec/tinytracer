#include <iostream>
#include <fstream>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <dirent.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <iostream>

// check if a process is 32-bit or 64-bit
bool is_32_bit(pid_t pid) {

    std::string filename = "/proc/" + std::to_string(pid) + "/exe";
    std::ifstream i(filename);
    i.seekg(4);
    int value = i.get();

    std::cout << "Got value " << std::hex << value << std::endl;
    assert(value == 1 || value == 2);
    return value == 1;
}

long long unsigned get_remote_base_address(pid_t pid) {
    std::string filename = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream i(filename);

    if(!i.is_open()) {
        throw std::runtime_error("Can't open /proc/child_pid/maps");
    }

    std::string line;
    std::getline(i, line);

    auto token = line.substr(0,line.find("-"));
    return std::stoull(token, nullptr, 16);
}

/* Similar to getline(), except gets process pid task IDs.
 * Returns positive (number of TIDs in list) if success,
 * otherwise 0 with errno set. */
size_t get_tids(pid_t **const listptr, size_t *const sizeptr, const pid_t pid)
{
    char     dirname[64];
    DIR     *dir;
    pid_t   *list;
    size_t   size, used = 0;

    if (!listptr || !sizeptr || pid < (pid_t)1) {
        errno = EINVAL;
        return (size_t)0;
    }

    if (*sizeptr > 0) {
        list = *listptr;
        size = *sizeptr;
    } else {
        list = *listptr = NULL;
        size = *sizeptr = 0;
    }

    if (snprintf(dirname, sizeof dirname, "/proc/%d/task/", (int)pid) >= (int)sizeof dirname) {
        errno = ENOTSUP;
        return (size_t)0;
    }

    dir = opendir(dirname);
    if (!dir) {
        errno = ESRCH;
        std::cerr << "Could not open dir task\n";
        return (size_t)0;
    }

    while (1) {
        struct dirent *ent;
        int            value;
        char           dummy;

        errno = 0;
        ent = readdir(dir);
        if (!ent)
            break;

        /* Parse TIDs. Ignore non-numeric entries. */
        if (sscanf(ent->d_name, "%d%c", &value, &dummy) != 1)
            continue;

        /* Ignore obviously invalid entries. */
        if (value < 1)
            continue;

        /* Make sure there is room for another TID. */
        if (used >= size) {
            size = (used | 127) + 128;
            list = (pid_t*)realloc(list, size * sizeof list[0]);
            if (!list) {
                closedir(dir);
                errno = ENOMEM;
                return (size_t)0;
            }
            *listptr = list;
            *sizeptr = size;
        }

        /* Add to list. */
        std::cout << "Found thread " << std::dec << value << "\n";
        list[used++] = (pid_t)value;
    }
    if (errno) {
        const int saved_errno = errno;
        closedir(dir);
        errno = saved_errno;
        return (size_t)0;
    }
    if (closedir(dir)) {
        errno = EIO;
        return (size_t)0;
    }

    /* None? */
    if (used < 1) {
        errno = ESRCH;
        return (size_t)0;
    }

    /* Make sure there is room for a terminating (pid_t)0. */
    if (used >= size) {
        size = used + 1;
        list = (pid_t*)realloc(list, size * sizeof list[0]);
        if (!list) {
            errno = ENOMEM;
            return (size_t)0;
        }
        *listptr = list;
        *sizeptr = size;
    }

    /* Terminate list; done. */
    list[used] = (pid_t)0;
    errno = 0;
    return used;
}
