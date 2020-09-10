#include <stdio.h>
#ifndef USERLAND_EXEC_H_
#define USERLAND_EXEC_H_	1

void ul_exec(char *progname, void *ELF_buf, size_t elf_buf_size, int argc, char **argv, char **envp);

#endif /* USERLAND_EXEC_H_ */
