#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include "../include/ul_execP.h"

extern unsigned int pgsz;  /* set in ul_save_elfauxv() */

struct ul_args {
	size_t	size;
	int	    cnt;
	char   *block;
};

ul_args_t * ul_save_args(int argc, char **argv) {
	ul_args_t *args;
	size_t	   len;
	int	       i;
	char      *str;
	

	if (argc > 0)
		for (i = 0, len = 0; i < argc; i++)
			len += strlen(argv[i]) + 1;
	else {
		/* Count them ourselves - env doesn't have envc. */
		argc = 0;
		char **p = argv;
		while (*p)
		{
			len += strlen(*p) + 1;
			++p;  /* move past ASCII Nul */
			++argc;
		}
	}

	args = ALLOCATE(sizeof(*args));

	args->size = len;
	args->cnt = argc;
	args->block = ALLOCATE(args->size);

	/* Do it this way because the values of argv[] or env[] may not actually
	 * exist as contiguous strings.  We will make them contiguous. */
	for (i = 0, str = args->block; i < argc; i++, str += strlen(str) + 1)
		strcat(str, argv[i]);

	return args;
}

void * ul_setup_stack( ul_args_t  *args, ul_args_t  *envp, ul_args_t  *auxvp, Elf32_Ehdr *elf, Elf32_Ehdr *interp){
	Elf32_auxv_t *aux, *excfn = NULL;
	char **av, **ev;
	char	*addr, *str, *esp;
	unsigned int *ptr;
	int	  argsize, i, j;

	/* Count bytes needed for new stack */
	argsize = 4 + strlen(args->block) + 1;  /* NULL at top of stack, executable file name */
	argsize += envp->size;                  /* environment strings */
	argsize += args->size;                  /* argument strings size */
	argsize += 4;  /* Do we really  need a NULL word here? */
	argsize += auxvp->cnt * sizeof(Elf32_auxv_t); /* Elf aux vector table */
	argsize += 4;                           /* NULL that ends envp[] */
	argsize += envp->cnt * sizeof(char *); /* table of pointers to env strings */
	argsize += 4;                           /* NULL that ends argv[] */
	argsize += args->cnt * sizeof(char *); /* table of pointers to argv strings */
	argsize += 4;                           /* argc */
	

	/* Allocate and align a new stack. */
	esp = (char *)ALIGN((unsigned int)alloca(ROUNDUP(argsize, pgsz)), 16);

	/* NOTE: The new stack for the userland-execed process lives
	 * *below* the bottom of the stack RIGHT NOW.  After returning from
	 * ul_setup_stack(), don't call anything that uses the call stack: that
	 * will roach this newly-constructed stack.  In fact, the code below
	 * does its own strcpy() and memcpy() equivalents, to the detriment of
	 * code quality.
	 */

	ptr = (unsigned int *)esp;

	*ptr++ = args->cnt;
	av = (char **)ptr;
	ptr += args->cnt;  /* skip over argv[] */
	*ptr++ = 0;

	ev = (char **)ptr;
	ptr += envp->cnt;  /* skip over envp[] */
	*ptr++ = 0;

	aux = (Elf32_auxv_t *)ptr;

	ptr = (unsigned int *)ROUNDUP((unsigned long)ptr + auxvp->size, sizeof(unsigned int));
	
	/* Copy ELF auxilliary vector table onto fake stack. */
	addr =  (char *)aux;
	for (j = 0; j < auxvp->size; ++j)
		addr[j] = auxvp->block[j];

	/* Fix up a few entries: kernel will have set up the AUXV
	 * for the user-land exec program, mapped in at a low address.
	 * need to fix up a few AUXV entries for the "real" program. */
	for (i = 0; i < auxvp->cnt; ++i)
	{
		switch (aux[i].a_type)
		{
		case AT_PHDR:  aux[i].a_un.a_val = (unsigned int)((char *)elf + elf->e_phoff); break;
		case AT_PHNUM: aux[i].a_un.a_val = elf->e_phnum; break;
		/* Some kernels give AT_BASE a zero value. */
		case AT_BASE:  aux[i].a_un.a_val = (unsigned int)interp; break;
		case AT_ENTRY: aux[i].a_un.a_val = (unsigned int)elf->e_entry; break;
		/* Not all glibc specify this, apparently. */
#ifdef AT_EXECFN
		case AT_EXECFN: excfn = &(aux[i]); break;
#endif
		}
	}

	*ptr++ = 0;

	/* Copy argv strings onto stack */
	addr =  (char *)ptr;
	str = args->block;

	for (i = 0; i < args->cnt; ++i)
	{
		av[i] = addr;
		for (j = 0; *str; ++j)
			*addr++ = *str++;
		*addr++ = *str++;  /* ASCII Nul */
	}

	ptr = (unsigned int *)ROUNDUP((unsigned int)addr, sizeof(unsigned int));
	*ptr = 0;

	/* Copy envp strings onto stack */
	addr =  (char *)ptr;
	str = envp->block;

	for (i = 0; i < envp->cnt; ++i)
	{
		ev[i] = addr;
		for (j = 0; *str; ++j)
			*addr++ = *str++;
		*addr++ = *str++;  /* ASCII Nul */
	}

	ptr = (unsigned int *)ROUNDUP((unsigned int)addr, sizeof(unsigned int));
	*ptr = 0;

	/* Executable name at top of stack.
	 * Not all kernels put the name at the top of the stack.
	 * RHEL old 2.6.18 kernels don't.
	 */
	if (excfn)
	{
		addr =  (char *)ptr;
		str = args->block;
		excfn->a_un.a_val = (unsigned int)addr;
		for (j = 0; *str; ++j)
			*addr++ = *str++;
		*addr++ = *str++;  /* ASCII Nul */

		ptr = (unsigned int *)ROUNDUP((unsigned int)addr, sizeof(unsigned int));
	}

	munmap(args->block, args->size);
	munmap(args, sizeof(*args));
	munmap(auxvp->block, auxvp->size);
	munmap(auxvp, sizeof(*auxvp));
	munmap(envp->block, envp->size);
	munmap(envp, sizeof(*envp));

	*ptr = 0;

	return ((void *)esp);
}

/* Get a copy of ELF auxilliary vector table. */
ul_args_t * ul_save_elfauxv(char **envp) {
	int cnt;
	ul_args_t *r = NULL;
	Elf32_auxv_t *q;
	unsigned int *p;

	/* Grope up the stack for Elf auxilliary vectors.
	 * Find NULL word (32-bit) after env string pointers.
	*/
	p = (unsigned int *)envp;
	while (*p != 0)
		++p;

	++p; /* skip the null word */

	for (cnt = 0, q = (Elf32_auxv_t *)p; q->a_type != AT_NULL; ++q)
	{
		/* Why get pagesize from the ELF aux vector?  Because dietlibc
		 * doesn't have a totally static version of getpagesize(), which
		 * means glibc gets used via a weak symbol in dietlibc. */
		if (AT_PAGESZ == q->a_type)
			pgsz = q->a_un.a_val;
		++cnt;
	}

	++cnt; /* The AT_NULL final entry */

	r = ALLOCATE(sizeof(*r));
	r->size = sizeof(*q) * cnt;
	r->cnt = cnt;
	r->block = ALLOCATE(r->size);
	memcopy((void *)r->block, (void *)p, r->size);

	return r;
}
