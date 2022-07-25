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
#include <set>


#include "ptrace_helpers.h"
#include "process.h"
#include "debugger.h"

/**
 * TODO
 *
 * parse a list of address from a file: DONE
 */


tracee_info g_child_info;
static std::string g_input_file = "addresses.txt";


void display_trace(long long unsigned addr, std::vector<bp::breakpoint> breakpoints, pid_t pid) {

    auto wanted_breakpoint = std::find_if(
            breakpoints.begin(), breakpoints.end(),
            [&addr](const bp::breakpoint x) { return x.address == addr;});

    std::cout << "[*] [" << std::dec << pid  <<  "] Breakpoint hit @ 0x"
              << std::hex << wanted_breakpoint->address
              << " (" << wanted_breakpoint->symbol
              << " )"
              << std::endl;
}

int attach(int pid, std::vector<symbol> symbols) {

    // attach to process. 
    _ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
    errno = 0;
    int ret = ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACECLONE);
    std::fprintf(stderr, "setoptions ret=%d err=%s\n", ret, strerror(errno));

    if(ret == -1) {
        std::cerr << "[!] Can't follow clones, quitting...\n";
        exit(-1);
    }

    pid_t *tid = 0;
    size_t tids = 0;
    size_t tids_max = 0;
    int r = 0;
    std::set<int>::iterator allThreadsIter;
    g_child_info.childs.insert(pid);

    /* Obtain task IDs. */
    tids = get_tids(&tid, &tids_max, pid);

    if (!tids) {
        std::cerr << "Failed to enumerate threads\n";
        exit(-1);
    }

    // Attach to all threads
    for (unsigned int t = 0; t < tids; t++) {

        // already attached to it
        if(tid[t] == pid)
            continue;

        do {
            r = ptrace(PTRACE_ATTACH, tid[t], (void *)0, (void *)0);
            if(r != -1) {
                std::cout << "[*] Attached to thread " << std::dec << tid[t] << std::endl;
                g_child_info.childs.insert(tid[t]);
            } else {
                std::cerr << "[!] Could not attach to " << std::dec << tid[t] << std::endl;
            }
        } while (r == -1L && (errno == EBUSY || errno == EFAULT || errno == ESRCH));
    }

    if(tids == 0) {
        std::cerr << "Failed to get threads\n";
        exit(-1);
    }

    // Dump the registers of each task.
    for (unsigned int t = 0; t < tids; t++)
        show_registers(stdout, tid[t], "");

    std::fprintf(stderr, "[*] Attached to process %d\n", pid);

    // setup all breakpoints
    std::vector<bp::breakpoint> breakpoints = set_breakpoints(pid, symbols);

    // ptrace attach will make the remote process to send a signal, catch it
    int wait_status;
    wait(&wait_status);

    // resume 
    resume_execution(pid);

    g_child_info.is_running = true;

    int status;

    struct user_regs_struct registers; // state of target's registers

    // handle debug events
    while(1) {

        //pid_t child_waited = waitpid(-1, &status, __WALL);
        int child_waited = wait(&wait_status);

        if(child_waited == -1) {

            std::cerr << "Got wait -1\n";
            exit(-1);
        }

        if(g_child_info.childs.find(child_waited) == g_child_info.childs.end())
        {
            printf("\nreceived unknown child %d\t", child_waited);
            g_child_info.childs.insert(child_waited);
        }

        if(WIFSTOPPED(wait_status) && WSTOPSIG(wait_status) == SIGTRAP)
        {
            pid_t new_child;
            if(((wait_status >> 16) & 0xffff) == PTRACE_EVENT_CLONE)
            {
                if(ptrace(PTRACE_GETEVENTMSG, child_waited, 0, &new_child) != -1)
                {
                    g_child_info.childs.insert(new_child);
                    _ptrace(PTRACE_CONT, new_child, 0, 0);

                    printf("\nchild %d created\n", new_child);
                }

                _ptrace(PTRACE_CONT, child_waited, 0, 0);
                continue;
            }
        }

        if(WIFEXITED(wait_status))
        {
            g_child_info.childs.erase(child_waited);
            printf("\nchild %d exited with status %d\t", child_waited, WEXITSTATUS(wait_status));

            if(g_child_info.childs.size() == 0)
                break;
        }
        else if(WIFSIGNALED(wait_status))
        {
            if(WTERMSIG(wait_status) == 5) {
                std::cerr <<  "[" << std::dec << child_waited << "]" <<  " maybe killed by signal 5, but trying anyway\n";
            } else {
                g_child_info.childs.erase(child_waited);
                printf("\nchild %d killed by signal %d\t", child_waited, WTERMSIG(wait_status));

                if (g_child_info.childs.size() == 0)
                    break;
            }
        }
        if (WIFSTOPPED(wait_status)) { // || WIFSIGNALED(wait_status)

            int status = 0;
            status = WSTOPSIG(wait_status);

            if (status == bp::BREAKPOINT_SIGNAL) {
                g_child_info.is_running = false;
                registers = get_regs(child_waited, registers);
                display_trace(registers.eip - 1, breakpoints, child_waited);
                // pause
                //getchar();

                registers.eip -= 1; // instruction pointer is one-step ahead because of the int 3 instruction
                long long unsigned ip = registers.eip;
                // re-set the original instruction and execute it in singlestep
                remove_breakpoint(child_waited, ip, breakpoints);

                set_regs(child_waited, registers);

                // single step
                _ptrace(PTRACE_SINGLESTEP, child_waited, 0, 0);
                wait(&wait_status);
                assert(WSTOPSIG(wait_status) == bp::BREAKPOINT_SIGNAL);

                // re-set the breakpoints
                enable_breakpoint(child_waited, ip, breakpoints);

                // continue
                resume_execution(child_waited);
                g_child_info.is_running = true;
            }
            else if(status == 4 || status == 11) {
                registers = get_regs(child_waited, registers);
                std::fprintf(stderr, "[!] Crash (signal %d)\n", status);
                std::fprintf(stderr, "[!] Original data at 0x%lx: 0x%lx\n", registers.eip, get_value(child_waited, registers.eip));
                exit(-1);
            } else if(status != 17 && status != 19){
                std::cout << "[!] Pid "  << std::dec << child_waited << " got signal " << status << " but won't do anything\n";
                if(resume_execution(child_waited) == -1) {
                    g_child_info.childs.erase(child_waited);
                }            }
            /*else if(status == 19) {
                std::cout << "[!] Ignoring signal 19 for pid " << child_waited << std::endl;
            }*/
            else {
                if(resume_execution(child_waited) == -1) {
                    g_child_info.childs.erase(child_waited);

                }
            }
        }
        else {
            std::cerr << "[!] Unknown event\n";
            std::cerr << "[!] exited: " << WIFEXITED(wait_status) << std::endl;
            std::cerr << "[!] signaled: " << WIFSIGNALED(wait_status) << std::endl;

            if(WIFSIGNALED(wait_status)) {
                std::cerr << "[!] Signal was " << WTERMSIG(wait_status) << std::endl;
                resume_execution(child_waited);
            }
        }
    }

    return 0;
}

void sig_handler(int s) {
    std::cout << "\n[*] Detaching...\n";
    cleanup(g_child_info.pid, g_child_info.breakpoints);

    for(auto it = g_child_info.childs.begin() ; it != g_child_info.childs.end() ; it++) {
        std::cout << "[*] Detaching from " << std::dec << *it << std::endl;
        _ptrace(PTRACE_DETACH, *it, NULL, NULL);
    }

    std::cout << "[*] Detaching from " << std::dec << g_child_info.pid << std::endl;
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