#include <sys/types.h>
#include <unistd.h>
#include <sys/user.h>



long 
_ptrace(int request, pid_t pid, void* addr, void* data);

/* Encapsulates a breakpoint. Holds the address at which the BP was placed
** and the original data word at that address (prior to int3) insertion.
*/
struct debug_breakpoint_t {
    long long unsigned addr;
    unsigned orig_data;
};
typedef struct debug_breakpoint_t debug_breakpoint;


debug_breakpoint* create_breakpoint(pid_t pid, void* addr);

/* Clean up the memory allocated for the given breakpoint.
** Note: this doesn't disable the breakpoint, just deallocates it.
*/
void cleanup_breakpoint(debug_breakpoint* bp);


/* Given a process that's currently stopped at breakpoint bp, resume
** its execution and re-establish the breakpoint.
** Return 0 if the process exited while running, 1 if it has stopped 
** again, -1 in case of an error.
*/
int resume_from_breakpoint(pid_t pid, debug_breakpoint* bp);


struct user_regs_struct get_regs(pid_t child_pid, struct user_regs_struct registers);

void set_regs(pid_t child_pid, struct user_regs_struct registers);

long long unsigned get_value(pid_t child_pid, long long unsigned address);

void set_breakpoint(long long unsigned bp_address, long long unsigned original_value, pid_t child_pid);

void revert_breakpoint(long long unsigned bp_address, long long unsigned original_value, pid_t child_pid);

void resume_execution(pid_t child_pid);

