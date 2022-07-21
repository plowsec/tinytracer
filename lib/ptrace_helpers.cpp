#include "ptrace_helpers.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>
#include <stdio.h>
#include <assert.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sstream> 
#include <iostream>
#include <string.h>
#include <fstream>
#include <unistd.h> 


/*

pwndbg> disas/r
Dump of assembler code for function genNumber:
   0x00005555555551d9 <+0>:     55      push   rbp
   0x00005555555551da <+1>:     48 89 e5        mov    rbp,rsp
=> 0x00005555555551dd <+4>:     89 7d fc        mov    DWORD PTR [rbp-0x4],edi
   0x00005555555551e0 <+7>:     8b 45 fc        mov    eax,DWORD PTR [rbp-0x4]
   0x00005555555551e3 <+10>:    05 39 05 00 00  add    eax,0x539
   0x00005555555551e8 <+15>:    5d      pop    rbp
   0x00005555555551e9 <+16>:    c3      ret    
End of assembler dump.
quitbg> 



splunk: 17:51 ~/dbg/Fuzzing/Caveman4 > ./tracer.bin `pgrep test.bin`                                                     
 [TRACE] Attached to process 104879.                                                                                                                      
Enable breakpoint @ 1431654874                                                                                                                            
Breakpoint hit                                                                                                                                            
eax = 0x0000007a87d376                                                                                                                                    
edx = 0x000000f7f9f20c                                                                                                                                    
edi = 0x0000007a87d376                                                                                                                                    
esi = 0x000000ffffe5e4                                                                                                                                    
eip = 0x000000555551db                                                                                                                                    
                                                                                                                                                          
Found the breakpoint (1431654874)                                                                                                                         
Original data at 0x555551da: 0x89e58948                                                                                                                   
Enable breakpoint @ 1431654874                                                                                                                            
Auto resume                                                                                                                                               
eax = 0x0000007a87d376                                                                                                                                    
edx = 0x000000f7f9f20c                                                                                                                                    
edi = 0x0000007a87d376                                                                                                                                    
esi = 0x000000ffffe5e4                                                                                                                                    
eip = 0x000000555551dd                                                                                                                                    
Crash (signal 11)                                                                                                                                         
Original data at 0x555551dd: 0x00000089   


splunk: 17:59 ~/dbg/Fuzzing/Caveman4 > ./tracer.bin `pgrep test.bin`                                                     
 [TRACE] Attached to process 105140.                                                                                                                      
Enable breakpoint @ 1431654877                                                                                                                            
Breakpoint hit                                                                                                                                            
eax = 0x0000000d0615ec                                                                                                                                    
edx = 0x000000f7f9f240                                                                                                                                    
edi = 0x0000000d0615ec                                                                                                                                    
esi = 0x000000ffffe5e4                                                                                                                                    
eip = 0x000000555551de                                                                                                                                    
                                                                                                                                                          
Found the breakpoint (1431654877)                                                                                                                         
Before data at 0x555551dd: 0x8bfc7dcc                                                                                                                     
Writing -1946387063                                                                                                                                       
Original data at 0x555551dd: 0x8bfc7d89                                                                                                                   
Enable breakpoint @ 1431654877                                                                                                                            
Auto resume                                                                                                                                               
eax = 0x0000000d0615ec                                                                                                                                    
edx = 0x000000f7f9f240                                                                                                                                    
edi = 0x0000000d0615ec                                                                                                                                    
esi = 0x000000ffffe5e4                                                                                                                                    
eip = 0x000000555551e0                                                                                                                                    
Crash (signal 11)                                                                                                                                         
Original data at 0x555551e0: 0x0000008b   
*/

int verbose = 1;


long 
_ptrace(int request, pid_t pid, void* addr, void* data)
{
    long r = ptrace( (__ptrace_request) request, pid, addr, data);
    if(r == -1){
        std::stringstream ss;
        ss  << " [PTRACE FAILURE] " 
            << " ; errno = " << errno 
            << " ; msg = '" << strerror(errno) 
            << "' \n";        
        throw std::runtime_error(ss.str());
    }
    return r;
}

// ptrace helper functions
struct user_regs_struct get_regs(pid_t child_pid, struct user_regs_struct registers) {                                                                                

    //printf("Getting registers\n");                                                                                                                                     
	int ptrace_result = ptrace(PTRACE_GETREGS, child_pid, 0, &registers);                                                                              
    if (ptrace_result == -1) {                                                                              
        fprintf(stderr, "dragonfly> Error (%d) during get_regs", errno);                                                                              
        perror("ptrace");                                                                              
        exit(errno);                                                                              
    }

    if(verbose) {

        printf("eax = 0x%lx\n", registers.rax);
        printf("edx = 0x%lx\n", registers.rdx);
        printf("edi = 0x%lx\n", registers.rdi);
        printf("esi = 0x%lx\n", registers.rsi);
        printf("eip = 0x%lx\n", registers.rip);

    }
    return registers;                                                                              
}

void set_regs(pid_t child_pid, struct user_regs_struct registers) {

    //printf("Setting registers\n");
    _ptrace(PTRACE_SETREGS, child_pid, 0, &registers);
}

long long unsigned get_value(pid_t child_pid, long long unsigned address) {
	//printf("Called Get_value\n");
	errno = 0;
    int tries = 0;

    do {
        long long unsigned value = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)address, 0);
        if (value == -1 && errno != 0) {
            fprintf(stderr, "Error (%d) during get_value(0x%lx) (pid = %d) ", errno, address, child_pid);
            perror("ptrace");
        } else {
            return value;
        }
    }
    while(tries++ < 10);
	exit(-1);	
}

void set_breakpoint(long long unsigned bp_address, long long unsigned original_value, pid_t child_pid) {
	printf("Setting breakpoint\n");
    long long unsigned breakpoint = (original_value & 0xFFFFFFFFFFFFFF00 | 0xCC);
    _ptrace(PTRACE_POKETEXT, child_pid, (void*)bp_address, (void*)breakpoint);

}

void revert_breakpoint(long long unsigned bp_address, long long unsigned original_value, pid_t child_pid) {
    //printf("Reverting breakpoint\n");
    _ptrace(PTRACE_POKETEXT, child_pid, (void*)bp_address, (void*)original_value);
}

void resume_execution(pid_t child_pid) {
    //printf("Resume execution\n");
    _ptrace(PTRACE_CONT, child_pid, 0, 0);
}
