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


/**
 * TODO
 *
 * parse a list of address from a file
 */

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
} tracee_info;


typedef struct symbol_t {
    long long unsigned address;
    std::string symbol;
} symbol;

static tracee_info g_child_info;
static std::string g_input_file = "addresses.txt";

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
        std::cout << "[*] Enabling breakpoint @ " << std::hex << wanted_breakpoint->address << std::endl;
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
        std::cout << "[*] Removing breakpoint @ " << std::hex << wanted_breakpoint->address << std::endl;
        revert_breakpoint(bp_addr, wanted_breakpoint->saved_opcodes, child_pid);
    } else {
        throw std::runtime_error("Could not restore breakpoint");
    }
}

void display_trace(long long unsigned addr, std::vector<bp::breakpoint> breakpoints) {

    auto wanted_breakpoint = std::find_if(
            breakpoints.begin(), breakpoints.end(),
            [&addr](const bp::breakpoint x) { return x.address == addr;});

    std::cout << "[*] Breakpoint hit @ 0x"
              << std::hex << wanted_breakpoint->address
              << " (" << wanted_breakpoint->symbol
              << " )"
              << std::endl;
}


int attach(int pid, std::vector<symbol> symbols) {

    // attach to process. 
    _ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
    std::fprintf(stderr, " [*] Attached to process %d\n", pid);

    // setup all breakpoints
    std::vector<bp::breakpoint> breakpoints = set_breakpoints(pid, symbols);

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
                g_child_info.is_running = false;
                registers = get_regs(pid, registers);
                display_trace(registers.rip - 1, breakpoints);
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
            throw std::runtime_error("[!] Unknown error");
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
        g_child_info.is_running = true;
    }

    return 0;
}

void sig_handler(int s) {
    printf("Detaching...\n");
    cleanup(g_child_info.pid, g_child_info.breakpoints);
    ptrace(PTRACE_DETACH, g_child_info.pid, NULL, NULL);
    exit(0);
}

std::vector<symbol> parse_addresses() {

    std::ifstream infile(g_input_file);
    std::vector<symbol> symbols;

    if(!infile.is_open()) {
        std::cerr << "Can't open address file\n";
        return symbols;
    }

    std::string line;
    while (std::getline(infile, line))
    {
        //std::cout << "Got address " << line << std::endl;
        auto index = line.find(",");
        auto address_field = line.substr(0, index);
        auto name = line.substr(index+1);

        if(name.find("thunk") == std::string::npos
            and name.find("tm_clones") == std::string::npos
            and name.find("start") == std::string::npos
            and name.find("frame_dummy") == std::string::npos
            and name.find("__do_global_") == std::string::npos
            and name.find("__libc_") == std::string::npos) {
            long long unsigned address = std::stoull(address_field, nullptr, 16);
            std::cout << "Address = 0x" << std::hex << address << " name = " << name << std::endl;
            symbol sym = {.address = address, .symbol = name};
            symbols.push_back(sym);
        }
    }

    infile.close();

    return symbols;
}

int main(int argc, char** argv) {

    if(argc != 2) {
        throw std::runtime_error("Invalid argument\n");
        return -1;
    }

    pid_t pid  = std::stoi(argv[1]);
    g_child_info.is_32_bit = is_32_bit(pid);
    g_child_info.pid = pid;

    if(g_child_info.is_32_bit)
        std::cout << "[*] Process is 32 bit\n";
    else
        std::cout << "[*] Process is 64 bit\n";

    struct sigaction sig_int_handler;
    sig_int_handler.sa_handler = sig_handler;
    sigemptyset(&sig_int_handler.sa_mask);
    sig_int_handler.sa_flags = 0;
    sigaction(SIGINT, &sig_int_handler, NULL);

    g_child_info.base_address = get_remote_base_address(pid);
    std::cout << "Base address is 0x" << std::hex << g_child_info.base_address << std::endl;
    std::vector<symbol> symbols = parse_addresses();
    attach(pid, symbols);

    return 0;
}