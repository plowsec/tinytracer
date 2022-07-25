
#ifndef DBG_DEBUGGER_H
#define DBG_DEBUGGER_H

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <fcntl.h>
#include <sstream>
#include <vector>
#include <assert.h>
#include <algorithm>
#include <set>

namespace bp {

    const unsigned int BREAKPOINT_SIGNAL = 5; // signal number for breakpoints

    typedef struct breakpoint_t {
        long long unsigned address; // address of the breakpoint
        long long unsigned saved_opcodes; // instruction overwritten by CC (int 3 bp)
        std::string symbol; // symbol name
    } breakpoint;
};

typedef struct tracee_info_t {
    pid_t pid; // backup the tracee pid here in order to detach with CTRL+C
    bool is_32_bit;
    bool is_running; // used to detach correctly
    long long unsigned base_address;
    std::vector<bp::breakpoint> breakpoints;
    std::set<pid_t> childs;
} tracee_info;


typedef struct symbol_t {
    long long unsigned address;
    std::string symbol;
} symbol;

extern tracee_info_t g_child_info;

std::vector<bp::breakpoint> set_breakpoints(pid_t child_pid, std::vector<symbol> symbols);
void cleanup(pid_t pid, std::vector<bp::breakpoint> breakpoints);

/**
 * @pre set_breakpoints was called and @param breakpoints is fully populated
 * @param child_pid remote process pid
 * @param bp_addr address where to put a breakpoint
 * @param breakpoints collection of known breakpoints
 */
void enable_breakpoint(pid_t child_pid, long long unsigned bp_addr, std::vector<bp::breakpoint> breakpoints);
void remove_breakpoint(pid_t child_pid, long long unsigned bp_addr, std::vector<bp::breakpoint> breakpoints);
void show_registers(FILE *const out, pid_t tid, const char *const note);



#endif //DBG_DEBUGGER_H
