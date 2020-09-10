#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <alloca.h>
#include "../include/ul_execP.h"



#define	is_loaded(p)	((p)->p_type == PT_LOAD ? 1 : 0)
#define	is_txt_segt(p)	((is_loaded(p)) && (p)->p_flags == (PF_X|PF_R))
#define	is_data_segt(p)	((is_loaded(p)) && (p)->p_flags == (PF_W|PF_R))
#define	segt_size(p)	((size_t)((p)->p_vaddr + (p)->p_memsz))
#define	load_addr(e)	((char *)(((e)->e_type == ET_DYN) ? (e) : NULL))

#define	FLAGS	(MAP_PRIVATE|MAP_ANONYMOUS)

static Elf32_Ehdr *load_linker_buf(void *linker_buf);

/*
 * Argument elf_buf points to a read-in or mapped-in ELF format
 * executable. load_elf_buf() creates all the various discrete
 * pieces of memory, at the correct addresses, with the correct
 * parts of elf_buf copied in to them, for the executable to run.
 */
static Elf32_Ehdr * load_elf_buf(void *elf_buf) {
	Elf32_Ehdr *r = NULL, *e = (Elf32_Ehdr *)elf_buf;
	Elf32_Phdr *phdr = (Elf32_Phdr *)((unsigned int)elf_buf + e->e_phoff);
	Elf32_Phdr *p;
	int	i;
	unsigned int highest_mapped_addr = 0;

	for (i = 0, p = phdr; i < e->e_phnum; i++, p++) { 
		char *ptr;
		unsigned int elf_prot = 0;
		unsigned int map_flags = 0;
		void *map_addr;
		size_t rounded_len;
		unsigned int x;
		

		if (p->p_type != PT_LOAD)
			continue;

		map_flags = FLAGS|MAP_FIXED;

		map_addr = (void *)ALIGNDOWN(p->p_vaddr, p->p_align);
		rounded_len = ROUNDUP(p->p_memsz, p->p_align);

		while ((x = (unsigned int)map_addr + rounded_len) <= p->p_vaddr + p->p_memsz)
			rounded_len += p->p_align;  /* rounded_len stays a multiple of p->p_align */

		if (x >= highest_mapped_addr)
		{
			if (MAP_FAILED == (ptr = mmap(map_addr, rounded_len, PROT_NONE, map_flags, -1, 0)))
				return NULL;

			/* Mark newly allocated memory so we can write to it */
			if (mprotect(ptr, rounded_len, PROT_WRITE))
				return NULL;

			highest_mapped_addr = x;

			if (!r) r = (Elf32_Ehdr *)ptr;
		}

		/* We need the exact load address, not the rounded down
	  	* version. Otherwis we copy to a garbage location.. */
		memcopy(
			(void *)p->p_vaddr,
			(char *)elf_buf + p->p_offset,
			p->p_filesz
		);

		if (p->p_offset) {
			if (mprotect(map_addr, rounded_len, PROT_WRITE | PROT_READ))
				return NULL;
		} else {
			if (mprotect(map_addr, rounded_len, PROT_READ | PROT_WRITE| PROT_EXEC))
				return NULL;

		}
	}

	return (Elf32_Ehdr *)r;
}

/* It appears that most kernels use 0x1000 byte pages.
 * But this global-scope variable also gets set in
 * ul_save_elfauxv(), from the ELF auxilliary headers.
 */
size_t pgsz = PAGESIZE;

/*
 * Loading ld.so, "ld-linux.so.2" or what have you, takes a slightly
 * different approach than load_elf_buf() uses. If you mmap() a few
 * pages for the .text segment of ld-linux.so.2, it's likely that
 * the kernel will map those pages in too close to something else.
 * The next mmap(), for the .bss segment of ld-linux.so.2, will overlap
 * that "something else".  At least some Linux 3.x kernels put MAP_ANONYMOUS
 * pages as high as possible, causing the probable overlap.
 */
static Elf32_Ehdr * load_linker_buf(void *linker_buf) {
	Elf32_Ehdr *e = (Elf32_Ehdr *)linker_buf;
	Elf32_Phdr *p, *phdr = (Elf32_Phdr *)((unsigned int)linker_buf + e->e_phoff);
	int	i;
	void *base_addr = NULL;
	unsigned int max_addr = 0;

	/* Find how many bytes to allocate for ld-linux.so.2 in a single
	 * chunk.  First, find the "high address" for it, based on 
	 * p->p_vaddr + p->p_memsz for each loadable Phdr. */
	for (i = 0, p = phdr; i < e->e_phnum; i++, p++)
	{
		unsigned int addr;
		if (p->p_type != PT_LOAD)
			continue;
		addr = p->p_vaddr + p->p_memsz;
		if (addr > max_addr) max_addr = addr;
	}

	/* Round up the high address to a page-size multiple. */
	max_addr = ROUNDUP(max_addr, pgsz);

	/* ld.so contains position independent code, so the "max address"
	 * actually constitutes size in bytes. */
	if (MAP_FAILED == (base_addr = mmap(0, max_addr, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)))
		return NULL;

	/* Go over the Phdrs again, marking pages writeable, copying appropriate
	 * pieces of linnker_buf into the right (relative) address, and then putting
	 * the ELF protections on the page(s) as specified in the Phdr. */
	for (i = 0, p = phdr; i < e->e_phnum; i++, p++)
	{ 
		unsigned int elf_prot = 0;
		void *prot_addr;
		size_t rounded_len;

		if (p->p_type != PT_LOAD)
			continue;

		prot_addr = (void *)ALIGNDOWN(base_addr + p->p_vaddr, pgsz);
		rounded_len = ROUNDUP((base_addr + p->p_vaddr + p->p_filesz - prot_addr), pgsz);
		/* Does a situation ever exist where p->p_vaddr + p->p_filesz > prot_addr + rounded_len?
		 * It certainly happens in load_elf_buf(), but because we just do one
		 * allocation for all of ld-linux.so.2, I don't think it can happen here.
		 */

		/* Mark mmapped memory so we can write to it */
		if (mprotect(prot_addr, rounded_len, PROT_WRITE))
			return NULL;

		/* Copy from linker_buf to the right (relative)
		 * address in the allocation. */
		memcopy(
			(void *)(base_addr + p->p_vaddr),
			(char *)linker_buf + p->p_offset,
			p->p_filesz
		);

		/* Protect it as specified. */
		if (p->p_flags & PF_R)
			elf_prot |= PROT_READ;
		if (p->p_flags & PF_W)
			elf_prot |= PROT_WRITE;
		if (p->p_flags & PF_X)
			elf_prot |= PROT_EXEC;

		if (mprotect(prot_addr,  rounded_len, elf_prot))
			return NULL;
	}

	return (Elf32_Ehdr *)base_addr;
}

/* Based on a filename, load any ELF run-time linker. */
static Elf32_Ehdr * load_linker(const char *fname) {
	Elf32_Ehdr	*e;
	struct stat	st;
	char *buf;
	int fd, sz;

	if (0 > (fd = open(fname, O_RDONLY)))
		return NULL;

	buf = mmap(NULL, 0x30000, PROT_READ, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED)
	{
		close(fd);
		return NULL;
	}

	e = load_linker_buf(buf);
	
	//munmap(buf, st.st_size);
	close(fd);

	return e;
}

/*
 * Assuming that ELF_buf points to an in-memory image of
 * an ELF file, create blocks of memory at correct addresses
 * specified by Phdrs of the ELF file.  Copy appropriate sections
 * of ELF_buf into those blocks of memory, and give them protections
 * as specified in the Phdrs.
 */
int ul_load_elf(uint8_t *ELF_buf, Elf32_Ehdr **elf, Elf32_Ehdr **interp) {
	Elf32_Ehdr	*e, *ei = NULL;
	Elf32_Phdr	*p, *ptab;
	int	i;
	
	e = (Elf32_Ehdr *)ELF_buf;
	ptab =  (Elf32_Phdr*)&ELF_buf[e->e_phoff];  

	/* check for a dynamic linker, and if there is one, load it */
	for (i = 0, p = ptab; i < e->e_phnum; i++, p++)
	{
		if (p->p_type == PT_INTERP)
		{
			if (NULL == (ei = load_linker((char *)((unsigned int)ELF_buf+p->p_offset))))
				return -1;
			break;
		}
	}

	if ((e = load_elf_buf(ELF_buf)) == NULL) {
		return -1;
	
	}

	/* initialize the heap for later use. */
	for (i = 0, p = ptab; i < e->e_phnum; i++, p++)
		if (is_data_segt(p))
			brk(load_addr(e) + segt_size(p));

	if (elf)
		*elf = e;
	if (interp)
		*interp = ei;

	return 0;
}

/*
 * Our own private memcpy() - this exists to help debug.
 * Getting an mprotect() address off some bytes can cause
 * a SIGSEGV.  This one at least lets us see where the
 * actually faulting address lies.
 */
void * memcopy(void *dest, const void *src, size_t n) {
	unsigned int i;
	unsigned char *d = (unsigned char *)dest;
	unsigned char *s = (unsigned char *)src;

/*
	printf("Copying %d bytes from %p to %p, last address %p\n",
		n, s, d, (void *)((unsigned int)d + n));
*/

	for (i = 0; i < n; ++i)
		d[i] = s[i];

	return dest;
}
