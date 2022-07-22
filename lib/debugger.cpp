#include "debugger.h"
#include "ptrace_helpers.h"
#include <iostream>

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

    if(!g_child_info.is_running) {
        struct user_regs_struct registers;
        registers = get_regs(pid, registers);
        registers.rip -= 1;
        set_regs(pid, registers);
    }

    for(auto &breakpoint: breakpoints) {
        //std::cout << "[*] Removing breakpoint @ " << std::hex << breakpoint.address << std::endl;
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