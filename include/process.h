
#ifndef DBG_PROCESS_H
#define DBG_PROCESS_H

#include <csignal>

bool is_32_bit(pid_t pid);
long long unsigned get_remote_base_address(pid_t pid);
size_t get_tids(pid_t **const listptr, size_t *const sizeptr, const pid_t pid);
#endif //DBG_PROCESS_H
