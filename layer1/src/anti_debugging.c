#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/ptrace.h>
#include "../include/anti_debugging.h"

int crc32(char * str, int size){
	int aux;
	unsigned int kk;
	char current_char;
	
	kk = 0xFFFFFFFF;
	size = strlen(str);
	
	for (int i = 0; i < size; i++){
		current_char = str[i];
		for (int k = 0; k < 8; k++){
			aux = kk ^ current_char;
			kk = kk >> 1;
			if (aux & 0x1)
				kk ^= 0xEDB88320;

			current_char = current_char >> 1;
		}
	}
	return kk;
}

char *get_proc_name(char *buff){
	char *init, *end, *name;

	init = strstr(buff, "\t");
	end = strstr(init, "\n");
	
	name = (char *) calloc(sizeof(char), end - init);
	memcpy(name, init + 1, end - init);
	name[end - init - 1] = 0x00;
	return name;
}

void check_parent() {
	char buff[24];
	char *proc_name;
	int fd, crc;

	snprintf(buff, 24, "/proc/%d/status", getppid());
	if((fd = open(buff, O_RDONLY)) < 0) {
		return;
	}
	memset(buff, '\0', 24);
	read(fd, buff, 24);
	close(fd);

	proc_name = get_proc_name(buff);
	crc = crc32(proc_name, strlen(proc_name));
	
	// r2 - radare2 - gdb - idaq - idaq64 - strace - linux_server - linux_serverx64
	if (!(crc - 0x6bf8a7f4) ||
	    !(crc - 0xb2cc0ecb) || 
	    !(crc - 0xef0b559f) || 
	    !(crc - 0x8cafe0da) || 
	    !(crc - 0x73752682) || 
		!(crc - 0x34f2038f) ||
		!(crc - 0xb67665d3) || 
	    !(crc - 0xdc699c1c))
		kill(0, SIGTERM);
	free(proc_name);
}

void check_ld_preload() {
	char *str = getenv("LD_PRELOAD");

	if(str == NULL) {
		putenv("LD_PRELOAD=ELFlock");
		if (strcmp(getenv("LD_PRELOAD"), "ELFlock"))
			kill(0, SIGTERM);
	} else {
		kill(0, SIGTERM);
	}
}
