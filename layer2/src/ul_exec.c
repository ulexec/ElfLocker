#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <alloca.h>
#include <elf.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "../include/ul_execP.h"

#define SET_STACK(esp) asm("\tmovl %0, %%esp\n" :: "r"(esp))
#define JMP_ADDR(addr) asm("\tjmp  *%0\n" :: "r" (addr))

static void ul_exec_common(void *ELF_buf, size_t elf_buf_size, ul_args_t *argv, ul_args_t *envp, ul_args_t *auxvp);

void ul_exec(char *progname, void *elf_buf, size_t elf_buf_sz, int argc, char **argv, char **env) {
	ul_args_t	 *argvp, *envp, *auxvp;
	if ((argvp = ul_save_args(argc, argv)) == NULL)
		return;

	if ((envp = ul_save_args(0, env)) == NULL)
		return;

	if ((auxvp = ul_save_elfauxv(env)) == NULL)
		return;
	
	ul_exec_common(elf_buf, elf_buf_sz, argvp, envp, auxvp);
}

static void (*entry)() = (void(*)())-1;

static void ul_exec_common( void *elf_buf, size_t elf_buf_sz, ul_args_t *argv, ul_args_t *envp, ul_args_t *auxvp) {
	Elf32_Ehdr	*elf, *interp;

	void	*esp;
	/* load the main binary, and if required the dynamic linker */
	if (ul_load_elf(elf_buf, &elf, &interp))
		return;

	entry = interp ? (void(*)())(((char *)interp) + interp->e_entry) :
			 (void(*)())elf->e_entry;

	esp = ul_setup_stack(argv, envp, auxvp, elf, interp);


	if (NULL == esp)
		return;
/*
	mprotect(elf, sizeof(Elf32_Ehdr), PROT_WRITE);
	mprotect(interp, sizeof(Elf32_Ehdr), PROT_WRITE);
	memset(elf, '\0', sizeof(Elf32_Ehdr));
	memset(interp, '\0', 4);
	mprotect(elf, sizeof(Elf32_Ehdr), PROT_EXEC);
	mprotect(interp, sizeof(Elf32_Ehdr), PROT_EXEC);
	printf("%p\n", elf);
	printf("%p\n", interp);
*/
	/* No longer need the memory area pointed to by elf_buf */
	//munmap(elf_buf, elf_buf_sz);

	/* initialize the stack. */
	/* Take care adding code here: the fake stack is *below*
	 * (at a smaller address) the current stack frame. If you
	 * call anything that uses the stack, you stand a good chance
	 * of overwriting the fake stack that ul_setup_stack() took
	 * such care to construct. */
	/* set the %esp */

//	asm volatile("int3");

	SET_STACK(esp);

	/* transfer control to the new image */
	JMP_ADDR(entry);

	/* if we get here, there are massive fucking problems, for a start
	 * our stack is fucked up, and we can't return(). Just crash out. */
}
