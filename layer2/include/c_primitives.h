#include <signal.h>

static inline long syscall6(long syscall, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6);
static inline long syscall3(long syscall, long arg1, long arg2, long arg3);
static inline long syscall2(long syscall, long arg1, long arg2);
static inline long syscall1(long syscall, long arg1);


int __exit(int exit_code);
int _write(int fd, const void* buf, int count);
void * _mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void * _malloc(size_t length);
int _mprotect(void *addr, size_t len, int prot);
void _memset(void *addr, size_t len);
int _sigaction(int signum, const struct sigaction *act,struct sigaction *oldact);
size_t _strlen(const uint8_t *s);
int _munmap(void *addr, size_t length);
void *_memcpy(uint8_t *dest, const uint8_t *src, size_t n);





