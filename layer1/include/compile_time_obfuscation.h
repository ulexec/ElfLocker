#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define PUSH 0x50
#define POP  0x58
#define MOV  0xB8
#define NOP  0x90
#define ADD  0x01
#define AND  0x21
#define XOR  0x31
#define OR   0x09
#define SBB  0x19
#define SUB  0x29
#define JMP  0xeb

#define weird __COUNTER__ + __LINE__
#define xstrt(...) xstr(__VA_ARGS__)
#define xstr(...) str(__VA_ARGS__)
#define str(...) #__VA_ARGS__
#define op(...) ".byte " __VA_ARGS__
#define junk(x) asm volatile (x);

#define STOP_TRACE 						\
	if(!fork()) { 						\
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) 	\
			kill(0, SIGKILL);			\
		ptrace(PTRACE_DETACH, 0, 0, 0);			\
		exit(0);					\
	}

#define ops(...) ".byte " xstr(__VA_ARGS__)
#define pre	\
	asm volatile(	"cpuid;   		\n\t" \
		     	"test %eax, %eax;	\n\t" \
		     	"call 1f+1;		\n\t" \
		     	"1:;			\n\t" \
			".byte 0x31; 		\n\t" \
			"pop %eax;		\n\t" \
		     	"je 1f+14;		\n\t" \
			"xadd %eax, 0x1023;	\n\t" \
			"jmp *%eax;		\n\t"); \
	junk(op(xstr(XOR+weird, ADD+weird)))			\
	asm volatile("1:;			\n\t"); \
	junk(op(xstr(SBB+weird, ADD+weird)))			\
	junk(op(xstr(XOR+weird, SUB+weird, NOP+weird, XOR+weird, SBB+weird, ADD+weird))) 	\
	junk(op(xstr(XOR+weird, SUB+weird, NOP+weird, XOR+weird, SBB+weird, ADD+weird)))
	

#define post \
	asm volatile("jmp 1f; 			\n\t");	\
	junk(op(xstr(ADD)))				\
	asm volatile("1:;			\n\t");	

#define obf(x) pre; x; post;


