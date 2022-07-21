
#ifndef DBG_PROCESS_H
#define DBG_PROCESS_H

#include <csignal>

bool is_32_bit(pid_t pid);
long long unsigned get_remote_base_address(pid_t pid);

#endif //DBG_PROCESS_H
