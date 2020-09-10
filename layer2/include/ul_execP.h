
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#ifndef USERLAND_EXEC_PRIV_H_
#define USERLAND_EXEC_PRIV_H_	1

typedef struct ul_args ul_args_t;


extern ul_args_t *ul_save_args(int argc, char **argv);
extern ul_args_t *ul_save_elfauxv(char **envp);
extern void ul_release_args(ul_args_t *args);
extern void * ul_setup_stack(ul_args_t *args, ul_args_t *envp, ul_args_t *auxvp, Elf32_Ehdr *elf,Elf32_Ehdr *interp);
extern int ul_load_elf(void *ELF_buf, Elf32_Ehdr **elf, Elf32_Ehdr **interp);
void *memcopy(void *dest, const void *src, size_t n);
void unmap(char *progname, int set_signal_handler);
void print_maps(void);

#define ROUNDUP(x, y)    ( ( ( x + ( y - 1 ) ) / y ) * y )
#define ALLOCATE(size)  \
      mmap(0, (size), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
#define	ALIGN(k, v)	(((k)+((v)-1))&(~((v)-1)))
#define	ALIGNDOWN(k, v)	((unsigned int)(k)&(~((unsigned int)(v)-1)))

/* Default VM page size in bytes.  Hopefully, ul_save_elfauxv() will find
 * the page size in the ELF auxilliary vector and use that value instead. */
#define PAGESIZE 0x1000

#endif /* USERLAND_EXEC_PRIV_H_ */
