#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/user.h>     
#include <stddef.h>     
#include <errno.h>  
#include <assert.h>
#include <wait.h>  
#include<signal.h>
#include<ucontext.h>

int safe_ptrace(int request, int pid, unsigned int* addr, void * data){
    	int result;
	errno = 0;
    	result = ptrace(request, pid, addr, data);
    	if(errno){
			kill(0, SIGILL);
		}
        return result;
}

static int debug_reg(int pid, int regnum){
    	return  safe_ptrace(
                	PTRACE_PEEKUSER, pid,
                	(unsigned int*)offsetof(struct user, u_debugreg[regnum]), 0
        	);
}

static int set_debug_reg(int pid, int regnum, unsigned int value){
    	return 	safe_ptrace(
                	PTRACE_POKEUSER, pid,
                	(unsigned int*)offsetof(struct user, u_debugreg[regnum]), (void*)value
        	);
}

static int bit_replace(int old_val, int lsb, int size, int new_val){
    	int mask = (-1 << (size+lsb)) | ((1 << lsb) - 1);
    	return (old_val & mask) | (new_val << lsb);
}

static void setup_control_reg(int pid, int regnum, int len, int when){
    	int dr7 = debug_reg(pid, 7);
    	
    	dr7 = bit_replace(dr7, 18 + 4*regnum, 2, len-1);
    	dr7 = bit_replace(dr7, 16 + 4*regnum, 2, when);
    	dr7 |= 3 << (2*regnum);
    	set_debug_reg(pid, 7, dr7);
}


int check_hardware_breakpoints(void) {
	pid_t child, parent;
	long ptrace_result;
	int returned_pid, status;
	struct sigaction s;

	parent = getpid();					
	prctl (PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);			// Allowing several ptrace tracers

	if (!fork()) { 
    int dr0, dr1, dr2, dr3;                                        								// Creating child thread; 
		safe_ptrace(PTRACE_ATTACH, parent, NULL, NULL);   		// Child
		
		returned_pid = waitpid(parent, &status, WUNTRACED);		// synchonization between threads
		assert(returned_pid == parent);
	
		dr0 = debug_reg(parent, 0);
		dr1 = debug_reg(parent, 1);
		dr2 = debug_reg(parent, 2);
		dr3 = debug_reg(parent, 3);

    	if ( dr0 || dr1 || dr2 || dr3){
      		kill(0, SIGBUS);
    	}
		safe_ptrace(PTRACE_CONT, parent, NULL, NULL); 			// resuming execution of parent
		exit(0);
	} else { 								// Parent
		wait(NULL);							// suspending parent temporarely
	}
	return 0; 
}
