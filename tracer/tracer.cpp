#include <iostream>
#include <string.h>
#include <fstream>
#include <unistd.h> 
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


#include "ptrace_helpers.h"
#include "process.h"

namespace bp {

    const unsigned int BREAKPOINT_SIGNAL = 5; // signal number for breakpoints

    typedef struct breakpoint_t {
        long long unsigned address; // address of the breakpoint
        long long unsigned saved_opcodes; // instruction overwritten by CC (int 3 bp)
    } breakpoint;
};

std::vector<bp::breakpoint> set_breakpoints(pid_t child_pid) {

    std::vector<unsigned long long> breakpoints_addr {0x00005555555551dd};
    std::vector<bp::breakpoint> breakpoints;
    uint64_t index = 0;

    for(auto &addr: breakpoints_addr) {
        long long unsigned current_address = breakpoints_addr[index++];
        long long unsigned saved_value = get_value(child_pid, current_address);
        bp::breakpoint new_bp = {.address = current_address, .saved_opcodes = saved_value};
        set_breakpoint(current_address, saved_value, child_pid);
        breakpoints.push_back(new_bp);
    }

    return breakpoints;
}


/**
 * @pre set_breakpoints was called and @param breakpoints is fully populated
 * @param child_pid remote process pid
 * @param bp_addr address where to put a breakpoint
 * @param breakpoints collection of known breakpoints
 */
void enable_breakpoint(pid_t child_pid, long long unsigned bp_addr, std::vector<bp::breakpoint> breakpoints) {

    auto wanted_breakpoint = std::find_if(
            breakpoints.begin(), breakpoints.end(),
            [&bp_addr](const bp::breakpoint x) { return x.address == bp_addr;});

    if(wanted_breakpoint != breakpoints.end()){
        std::cout << "[*] Enabling breakpoint @ " << std::hex << wanted_breakpoint->address << std::endl;
        set_breakpoint(bp_addr, wanted_breakpoint->saved_opcodes, child_pid);
    } else {
        std::runtime_error("Could not enable breakpoint");
    }
}

void remove_breakpoint(pid_t child_pid, long long unsigned bp_addr, std::vector<bp::breakpoint> breakpoints) {

    auto wanted_breakpoint = std::find_if(
            breakpoints.begin(), breakpoints.end(),
            [&bp_addr](const bp::breakpoint x) { return x.address == bp_addr;});

    if(wanted_breakpoint != breakpoints.end()){
        std::cout << "[*] Removing breakpoint @ " << std::hex << wanted_breakpoint->address << std::endl;
        revert_breakpoint(bp_addr, wanted_breakpoint->saved_opcodes, child_pid);
    } else {
        std::runtime_error("Could not restore breakpoint");
    }
}

int attach(int pid) {

    // attach to process. 
    _ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
    std::fprintf(stderr, " [*] Attached to process %d\n", pid);

    // setup all breakpoints
    std::vector<bp::breakpoint> breakpoints = set_breakpoints(pid);

    // ptrace attach will make the remote process to send a signal, catch it
    int wait_status;
    wait(&wait_status);

    // resume 
    resume_execution(pid);

    struct user_regs_struct registers; // state of target's registers

    // handle debug events
    while(1) {

        wait(&wait_status);
        
        if (WIFSTOPPED(wait_status)) {

            int status = WSTOPSIG(wait_status);
            if (status == bp::BREAKPOINT_SIGNAL) {
                std::cout << "[+] Breakpoint hit\n";
                registers = get_regs(pid, registers);

                // pause
                getchar();
            }
            else {
                registers = get_regs(pid, registers);
                std::fprintf(stderr, "[!] Crash (signal %d)\n", wait_status);
                std::fprintf(stderr, "[!] Original data at 0x%lx: 0x%lx\n", registers.rip, get_value(pid, registers.rip));
                exit(-1);
            }
        }
        else {
            std::runtime_error("[!] Unknown error");
        }

        registers.rip -= 1; // instruction pointer is one-step ahead because of the int 3 instruction
        long long unsigned ip = registers.rip;
        // re-set the original instruction and execute it in singlestep
        remove_breakpoint(pid, ip, breakpoints);

        set_regs(pid, registers);

        // single step
        _ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        wait(&wait_status);
        assert(WSTOPSIG(wait_status) == bp::BREAKPOINT_SIGNAL);

        // singlestep again for debugging //TODO remove me
        _ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        wait(&wait_status);
        assert(WSTOPSIG(wait_status) == bp::BREAKPOINT_SIGNAL);

        // re-set the breakpoints
        enable_breakpoint(pid, ip, breakpoints);

        // continue
        resume_execution(pid);
    }

    return 0;
}

int main(int argc, char** argv) {

    if(argc != 2) {
        std::runtime_error("Invalid argument");
        return -1;
    }

    pid_t pid  = std::stoi(argv[1]);
    bool is_32_bit_proc = is_32_bit(pid);

    if(is_32_bit_proc)
        std::cout << "[*] Process is 32 bit\n";
    else
        std::cout << "[*] Process is 64 bit\n";

    attach(pid);

    return 0;
}