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
#include <string.h>
#include<signal.h>
#include<ucontext.h>

extern void sigHandler();
extern void case9(void);
extern void case9_end(void);
enum { EXECUTE=0, WRITE=1, READ_WRITE=3 };


void my_delta1(void) {
	size_t size = case9_end - case9;
	unsigned char *case9_bytes = (unsigned char*)case9;
	int i;
	
	for(i = 0; i < size; i++) {
		*(unsigned char*)(case9_bytes + i) ^= 0xff; 
	}
	
	puts("");
	
	return;
}

void my_delta0(void) {
	set_hbreak(0, 0, 0);
    set_hbreak(0, 0, 1);
	set_hbreak(0, 0, 2);
	set_hbreak(0, 0, 3);

    unset_hbreak_handler();
	case9();
	return;
}

int safe_ptrace(int request, int pid, unsigned int* addr, void * data){
    	int result;
		errno = 0;
    	result = ptrace(request, pid, addr, data);
		if(errno){
			kill(0, SIGBUS);
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


static void sig_handler(int nsig, siginfo_t *siginfo, void *ptr_context) {
	int val;
	switch(nsig){
		case SIGTRAP:
			{
				int reg_esi;
				unsigned int delta;
		
				asm volatile ("movl %%esi, %0;" : "=g" (reg_esi));	
				ucontext_t *context = (ucontext_t *)ptr_context;
                if(reg_esi == 1) 
                    my_delta0();
                else
                    my_delta1();
			}
		break;
	}
	return;
}

void set_hbreak_handler(void) {
    struct sigaction s;

	s.sa_sigaction = sig_handler;
	s.sa_flags = SA_SIGINFO;
	sigaction(SIGTRAP, &s, NULL);
    return;
} 

void set_hbreak(unsigned long *target, int type, int n) {
	pid_t child, parent;
	int returned_pid, status;
	parent = getpid();					
	//prctl (PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);			// Allowing several ptrace tracers

	if (!fork()) { 								// Creating child thread; 
		safe_ptrace(PTRACE_ATTACH, parent, NULL, NULL);   		// Child
		
		returned_pid = waitpid(parent, &status, WUNTRACED);		// synchonization between threads
		//assert(returned_pid == parent);
	
		set_debug_reg(parent, n, (unsigned int)target);		// setting EXECUTE watchpoint at function var 'my_test' on dr0
		setup_control_reg(parent, n, sizeof(char), type); 		// updating dr7 with attributes of dr0
		
		safe_ptrace(PTRACE_CONT, parent, NULL, NULL); 			// resuming execution of parent
		exit(0);
	} else { 								// Parent
		wait(NULL);							// suspending parent temporarely
    }
	return;
}

int check_hbreaks_if_modified(void) {
	pid_t child, parent;
	long ptrace_result;
	int returned_pid, status, return_value = 0;

	parent = getpid();					

	if (!fork()) { 
        int dr0, dr1, dr2, dr3;                                        								// Creating child thread; 
		safe_ptrace(PTRACE_ATTACH, parent, NULL, NULL);   		// Child
		
		returned_pid = waitpid(parent, &status, WUNTRACED);		// synchonization between threads
		
		dr0 = debug_reg(parent, 0);
		dr1 = debug_reg(parent, 1);
		dr2 = debug_reg(parent, 2);
		dr3 = debug_reg(parent, 3);

    	if ( dr0 || dr1 || dr2 || dr3){
			kill(0, SIGBUS);
		}
		set_debug_reg(parent, 0, (unsigned int)&return_value);		// setting EXECUTE watchpoint at function var 'my_test' on dr0
		setup_control_reg(parent, 0, sizeof(char), WRITE);
		safe_ptrace(PTRACE_CONT, parent, NULL, NULL); 			    // resuming execution of parent
		exit(0);
	} else {
		wait(NULL);
        return_value = 0;	
		my_delta0();
	}
	my_delta0();
	return 0; 
}

void unset_hbreak_handler(void) {
    struct sigaction s;

    memset(&s, 0, sizeof(s));
	s.sa_flags = SA_SIGINFO;
	sigemptyset(&s.sa_mask);
    s.sa_handler = sigHandler;
    sigaction(SIGTRAP, &s, NULL);
}

void check_hbreaks() {
    int val;
	
    prctl (PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);			// Allowing several ptrace tracers
    set_hbreak_handler();
    check_hbreaks_if_modified();
    return;
}