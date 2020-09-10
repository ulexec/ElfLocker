#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>    /* strtoul() */
#include <sys/types.h> /* stat(), open() */
#include <sys/stat.h> 
#include <fcntl.h>    
#include <unistd.h>   
#include <sys/mman.h> 
#include <signal.h>
#include <ctype.h>
#include <sys/ptrace.h>
#include "../include/ul_exec.h"
#include "../include/ul_execP.h"
#include "../include/huffman.h"
#include "../include/compile_time_obfuscation.h"
#include "../include/anti_debugging.h"
#include "../include/block_cipher.h"

extern void switch_main();
extern int switch_main_size;

unsigned int text_addr;
extern uint32_t etext;
unsigned text_size;
uint32_t *image_base, offset, size;
Elf32_Ehdr *ehdr;
struct sigaction s1;


void  sigHandler(int nsig, siginfo_t *siginfo, void *context) {
	switch(nsig){
		case SIGTRAP: 
			{		
				int ret;
				uint32_t *image_base = (uint32_t*)((text_addr >> 16) << 16);
				Elf32_Ehdr *ehdr = (Elf32_Ehdr*)image_base;
				
				ret = mprotect(ehdr, sizeof(Elf32_Ehdr), PROT_WRITE);
				if(ret == -1) {
					//perror("mprotect");
					exit(-1);
				}

				memset(ehdr, '\0', sizeof(Elf32_Ehdr));
				ret = mprotect(image_base, 4069, PROT_NONE);
				if (ret == -1) {
					//perror("mprotect\n");
					exit(-1);
				}
			}
		break;

		case SIGSEGV:
			{
				 int i;
				 uint8_t *addy = (uint8_t*)(((uint32_t)(siginfo->si_addr)) & ~4095);
				 
				if(mprotect(addy, 4096, PROT_READ | PROT_EXEC |PROT_WRITE) == -1) {
					//perror("mprotect");
					exit(-1);
				}
				addy = (uint8_t*)text_addr;
				decrypt_buff(addy, text_size);
				text_addr = 0;
			}				
		break;
	}
	return;
}

void sigill_handler(int nsig, siginfo_t *siginfo, void *context) {
	switch(nsig){
		case SIGILL:
			{
				ucontext_t *lcontext = (ucontext_t*)context;
				uint8_t *badinst = siginfo->si_addr;
				*(uint8_t*)badinst = '\x90';

				image_base = (uint32_t*)(((unsigned int)&etext >> 16) << 16);			       
				ehdr = (Elf32_Ehdr*)image_base;	
				size = *(uint32_t*)&ehdr->e_ident[12];
				*(uint8_t*)(badinst + 1) = '\x90';

				offset = *(uint32_t*)&ehdr->e_ident[8];
				text_addr = ehdr->e_shoff;
				text_size = ehdr->e_flags;
	
				s1.sa_sigaction = sigHandler;
				s1.sa_flags = SA_SIGINFO;
				*(uint8_t*)(badinst + 2) = '\x90';
			}				
		break;
	}
	return;
}

int main(int argc, char **argv, char **envp) {
	struct sigaction s2;
	
	s2.sa_flags = SA_ONSTACK | SA_RESTART | SA_SIGINFO;
	s2.sa_sigaction = sigill_handler;
	if((sigaction(SIGILL, &s2, NULL)) < 0) {
				exit(-1);
	}
	asm volatile(".byte 0x0F, 0x0B, 0xc3"); // UD2, ret
	switch_main(argc, argv, envp);
}


// 1 - crc de segmento text.
// 2 - hacer que nose intuitivo saber si el crc es correcto o incorrecto
// 3 - numero de cases es flexible
