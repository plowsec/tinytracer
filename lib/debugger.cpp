#include "debugger.h"
#include "ptrace_helpers.h"
#include <iostream>
#include <csignal>

std::vector<bp::breakpoint> set_breakpoints(pid_t child_pid, std::vector<symbol> symbols) {

    //std::vector<unsigned long long> breakpoints_addr {0x56556240};//{0x00005555555551dd};
    std::vector<bp::breakpoint> breakpoints;
    uint64_t index = 0;

    for(auto &addr: symbols) {

        auto current_symbol = symbols.at(index++);
        long long unsigned current_address = current_symbol.address;

        if(current_address < g_child_info.base_address) {
            current_address += g_child_info.base_address;
            std::cout << "[*] RVA to VA: " << current_address << std::endl;
        }

        long long unsigned saved_value = get_value(child_pid, current_address);

        bp::breakpoint new_bp = {
                .address = current_address,
                .saved_opcodes = saved_value,
                .symbol = current_symbol.symbol
        };

        std::cout << "[*] bp @ " << current_address << "( " << current_symbol.symbol << " ) " << std::endl;
        set_breakpoint(current_address, saved_value, child_pid);
        breakpoints.push_back(new_bp);
    }

    g_child_info.breakpoints = breakpoints;
    return breakpoints;
}

void cleanup(pid_t pid, std::vector<bp::breakpoint> breakpoints) {

    if(g_child_info.is_running) {
        kill(pid, SIGSTOP);
    } else {
        struct user_regs_struct regs;
        long r;

        r = ptrace(PTRACE_GETREGS, pid, &regs, &regs);

        if (r == -1L) {
            std::cerr << "Can't cleanup pid " << pid << std::endl;
        } else {
            regs.eip -= 1;
            _ptrace(PTRACE_SETREGS, pid, &regs, &regs);
        }
    }

    for(auto &breakpoint: breakpoints) {
        std::cout << "[*] Removing breakpoint @ " << std::hex << breakpoint.address << std::endl;
        revert_breakpoint(breakpoint.address, breakpoint.saved_opcodes, pid);
    }
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
        //std::cout << "[*] Enabling breakpoint @ " << std::hex << wanted_breakpoint->address << std::endl;
        set_breakpoint(bp_addr, wanted_breakpoint->saved_opcodes, child_pid);
    } else {
        throw std::runtime_error("Could not enable breakpoint");
    }
}

void remove_breakpoint(pid_t child_pid, long long unsigned bp_addr, std::vector<bp::breakpoint> breakpoints) {

    auto wanted_breakpoint = std::find_if(
            breakpoints.begin(), breakpoints.end(),
            [&bp_addr](const bp::breakpoint x) { return x.address == bp_addr;});

    if(wanted_breakpoint != breakpoints.end()){
        //std::cout << "[*] Removing breakpoint @ " << std::hex << wanted_breakpoint->address << std::endl;
        revert_breakpoint(bp_addr, wanted_breakpoint->saved_opcodes, child_pid);
    } else {
        throw std::runtime_error("Could not restore breakpoint");
    }
}

void show_registers(FILE *const out, pid_t tid, const char *const note)
{
    struct user_regs_struct regs;
    long                    r;

    do {
        r = ptrace(PTRACE_GETREGS, tid, &regs, &regs);
    } while (r == -1L && errno == ESRCH);
    if (r == -1L)
        return;

#if (defined(__x86_64__) || defined(__i386__)) && __WORDSIZE == 64
    if (note && *note)
        fprintf(out, "Task %d: RIP=0x%016lx, RSP=0x%016lx. %s\n", (int)tid, regs.rip, regs.rsp, note);
    else
        fprintf(out, "Task %d: RIP=0x%016lx, RSP=0x%016lx.\n", (int)tid, regs.rip, regs.rsp);
#elif (defined(__x86_64__) || defined(__i386__)) && __WORDSIZE == 32
    if (note && *note)
        fprintf(out, "Task %d: EIP=0x%08lx, ESP=0x%08lx. %s\n", (int)tid, regs.eip, regs.esp, note);
    else
        fprintf(out, "Task %d: EIP=0x%08lx, ESP=0x%08lx.\n", (int)tid, regs.eip, regs.esp);
#endif
}