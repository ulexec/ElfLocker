/* $Id: unmap.c,v 1.6 2012/07/12 23:33:31 bediger Exp $ */
#include <stdio.h>   /* BUFSIZ, snprintf(), fopen(), fread(), etc */
#include <stdlib.h>  /* strtoul() */
#include <errno.h>
#include <string.h>
#include <unistd.h>  /* getpid() */
#include <sys/mman.h>
#include <signal.h>
#include <elf.h>
#include "../include/ul_execP.h"

#ifdef SIGNAL_HANDLER
/* signal handler function in .so, so that it doesn't get
 * munmapped along with the .text segment.  If something in
 * unmap() segfaults, this will let us know. */
void
handler(int signo, siginfo_t *info, void *p) {
	ucontext_t *ctxt = p;
	fprintf(stderr, "enter handler(%d)\n", signo);
	fprintf(stderr, "siginfo_t at %p, ucontext_t at %p\n", info, ctxt);
	fprintf(stderr, "si_signo %d\n", info->si_signo);
	fprintf(stderr, "si_errno %d\n", info->si_errno);
	fprintf(stderr, "si_code %d\n", info->si_code);
	if (signo == SIGSEGV)
	{
		switch (info->si_code)
		{
		case SEGV_MAPERR: fprintf(stderr, "Address not mapped to object.\n"); break;
		case SEGV_ACCERR: fprintf(stderr, "Invalid permissions for mapped object.\n"); break;
		}

		fprintf(stderr, "Faulting instruction/memory ref: %p\n",
			info->si_addr);
	}
	exit(99);
}
#endif

void
unmap(char *progname, int set_handler) {
	char buf[BUFSIZ], *p;
	int c;
	FILE *fin;
#ifdef SIGNAL_HANDLER
	struct sigaction act, oact;

	if (set_handler)
	{
		act.sa_flags = SA_SIGINFO;
		act.sa_sigaction = handler;

		if (sigaction(SIGSEGV, &act, &oact))
			fprintf(stderr, "Problem setting handler for SIGSEGV: %s\n",
				strerror(errno));
	}
#endif

	fin = fopen("/proc/self/maps", "r");

	p = &buf[0];

	/* Read contents of /proc/self/maps into buf, one byte at
	 * a time.  When we hit a newline-valuded byte, we know we've
	 * read an entire line of text, and we can now act on it. */
	while (EOF != (c = fgetc(fin)))
	{
		if ('\n' != c)
			*p++ = c;
		else {
			*p = '\0';
			/* When a line from /proc/self/maps shows up as having been
			 * mapped in from this running program, ld.so or libc, unmap it.
			 * This will keep the exec'd program's address space a lot
			 * cleaner.  But even a 32-bit address space can hold 2 copies
			 * of glibc without ill effects, so you don't really have to
			 * munmap() anything other than the program calling ul_exec() */
			if (strstr(buf, progname) || strstr(buf, "libdl")
				|| strstr(buf, "/lib/ld-") || strstr(buf, "libc"))
			{
				char *u;
				char *first, *second;
				unsigned int low, high;

				u = strchr(buf, ' ');
				*u = '\0';

				first = buf;

				second = strchr(first, '-');
				*second = '\0';
				++second;

				low = strtoul(first, NULL, 0x10);
				high = strtoul(second, NULL, 0x10);

				if (munmap((void *)low, high-low))
					fprintf(stderr, "munmap 0x%x (%d) bytes at 0x%x failed: %s\n",
						high-low, high-low, low, strerror(errno));

			}

			p = &buf[0];
		}
	}

	fclose(fin);
}

#ifdef NEEDITNOW
/* A function useful in debugging, but nowhere else. */
void print_maps(void) {
	char buf[BUFSIZ];
	int cc;
	FILE *fin;

	fin = fopen("/proc/self/maps", "r");

	while (0 < (cc = fread(buf, 1, sizeof(buf), fin)))
		fwrite(buf, 1, cc, stdout);

	fclose(fin);
}
#endif
