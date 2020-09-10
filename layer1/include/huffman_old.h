#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <elf.h>
#include <ctype.h>
#include <signal.h>
#include <sys/ptrace.h>
#define QSIZE 0x100
#define PAGE_SIZE 0x1000
#define PAGE_ROUND_UP(x) ( (((unsigned int)(x)) + PAGE_SIZE-1)  & (~(PAGE_SIZE-1)) ) 

typedef struct __node_t {
	int freq;
	char key;
	bool leaf;
	struct __node_t *left, *right;
} Node;

extern int freqs[QSIZE];
extern char *decoding;
extern void ul_exec(char *progname, void *ELF_buf, size_t elf_buf_size, int argc, char **argv, char **envp);
//extern int decode_bin(Node *root, Node *original, char *bytes, int len);
int decode_bin(Node *root, Node *original, char *bytes, int len, uint8_t *decoded);
extern int str2bin(char* bin);
extern char * generate_elf_ordered_bitstream(uint8_t *elf, int size);
extern void init_elf_hash_map(uint8_t *elf, int size, int *freqs);
extern unsigned char *binary2hex(char *ord_bitstream, int rsize, int *size);
extern unsigned char * dc_bin2hex(char *ord_bitstream, int *size);
extern void qinsert(Node **nodes, Node *node);
extern void insert_node(Node **nodes, Node *left, Node *right, int freq, int key);
extern void qdelete(Node **nodes, int idx);
extern int get_map_len(int *freqs);
extern void encode(Node *root, int len, char *code, int nleaf_nodes);
extern void insert_leaf_nodes(int *freqs, Node **nodes);
extern Node *create_btree(int *freqs, Node **nodes);
extern char * generate_ordered_bitstream(int sect_sz, int sect_off, uint8_t *elf);

