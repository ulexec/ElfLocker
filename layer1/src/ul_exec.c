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
#include <sys/prctl.h>
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

static void ul_exec_common( void *elf_buf, size_t elf_buf_sz, ul_args_t *argv, ul_args_t *envp, ul_args_t *auxvp) {
	Elf32_Ehdr	*elf, *interp;
	void	(*entry)();
	void	*esp;

	prctl(PR_SET_DUMPABLE, 0);
	
	if (ul_load_elf(elf_buf, &elf, &interp))
		return;

	entry = interp ? (void(*)())(((char *)interp) + interp->e_entry) :
			 (void(*)())elf->e_entry;
	esp = ul_setup_stack(argv, envp, auxvp, elf, interp);

	if (NULL == esp) return;

	asm volatile(".byte 0xf1"); // icebp
	SET_STACK(esp);
	JMP_ADDR(entry);
}
