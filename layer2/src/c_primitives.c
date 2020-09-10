#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>

 static inline long syscall6(long syscall, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
	long ret;

	asm  volatile("movl %1, %%eax;\n"
		      "movl %2, %%ebx;\n"
		      "movl %3, %%ecx;\n"
		      "movl %4, %%edx;\n"
		      "movl %5, %%esi;\n"
		      "movl %6, %%edi;\n"
		      "movl %7, %%ebp;\n"
		      "int $0x80;\n"
    		: "=a" (ret)
    		: "g" (syscall) ,"g" (arg1), "g" (arg2), "g" (arg3), "g" (arg4), "g" (arg5), "g" (arg6));
	return ret;
}

 static inline long syscall3(long syscall, long arg1, long arg2, long arg3) {
	long ret;
	asm volatile("int $0x80;"	: "=a" (ret)
					: "a" (syscall)
					, "b" (arg1)
					, "c" (arg2)
					, "d" (arg3)
					: "memory");
	return ret;
}

static inline long syscall2(long syscall, long arg1, long arg2) {
	long ret;
	asm volatile("int $0x80;"	: "=a" (ret)
					: "a" (syscall)
					, "b" (arg1)
					, "c" (arg2)
					: "memory");
	return ret;
}

static inline long syscall1(unsigned long syscall, long arg1) {
	long ret;

	asm volatile("int $0x80;"	: "=a" (ret)
					: "a" (syscall)
				, "b" (arg1)
					: "memory");
	return ret;
}

int __exit(int exit_code) {
	return syscall1(1, exit_code);
} 

int _write(int fd, const void* buf, int count) {
	return syscall3(4, fd, (long)buf, count);
}

void * _mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset){
	return (void *)syscall6(192, (unsigned long)addr, length, prot, flags, fd, offset);
}

void * _malloc(size_t length){
	length = (length <= 4096) ? 4096 : 4096 * ((length / 2096) + 1);  
	void *mem = _mmap(NULL, length, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
	return mem;
}

int _mprotect(void *addr, size_t len, int prot) {
	return syscall3(125, (long)addr, len, prot);
}

void _memset(void *addr, size_t len) {
	asm volatile(	
		"movl %0, %%ecx;\n"
		"movl %1, %%edi;\n"
		"xorb %%al, %%al;\n"
		"rep stosb;\n"
		: : "g" (len),  "g" (addr));	
}

int _sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
	return syscall3(67, signum, (long)act, (long)oldact);
}

int _munmap(void *addr, size_t length) {
	return syscall2(11, (long)addr, length);
}

void *_memcpy(uint8_t *dest, const uint8_t *src, size_t n) {
	int i = 0;
	while(i++ != n) dest[i] = src[i];
	return dest;
}

size_t _strlen(const uint8_t *s) {
	int ret = 0;
	while(s[ret] != 0) ret++;
	return ret;
}

int _open(const char *pathname, int flags) {
	return syscall2(2, pathname, flags);
}

int _fstat(int fd, struct stat *buf) {
	return syscall2(5, fd, buf);
}

int _close(int fd) {
	return syscall1(3, fd);
}

char * _strcat(char *dest, const char *src) {
    char *rdest = dest;

    while (*dest)
      dest++;
    while (*dest++ = *src++);
    return rdest;
}
