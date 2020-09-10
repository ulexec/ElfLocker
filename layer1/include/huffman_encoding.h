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

static int qtail = -1;
static char *encoding[QSIZE] = {0}, *decoding, *compressed;

typedef struct __node_t {
	int freq;
	char key;
	bool leaf;
	struct __node_t *left, *right;
} Node;


int decode_bin(Node *root, Node *original, char *bytes, int len) {
	int nbyte = 0, n = 0, nbit = 7;
	char byte = bytes[0];	
	
	while( nbyte < len ) {
		while (nbit >= 0) {
			if(root->leaf){
				*(decoding + n++) = root->key;
				root = original;
			}
	  		root = (byte & (0x1 << nbit--)) ? root = root->right : root->left;		
		}
		nbit = 7;
		byte = bytes[++nbyte];
	}
	return n;

}

int str2bin(char* bin) {
	char* start = &bin[0];
	int total = 0;

	while (*start){
 		total <<= 1;
 		if (*start++ == '1') total ^= 1;
	}
	return total;
}

char * generate_elf_ordered_bitstream(uint8_t *elf, int size) {
	char *ord_bitstream = (char*)calloc(sizeof(char), size*30);
	int i, j = 0;
	
	for( i = 0; i < size; i++) {
		char *buf = strdup(encoding[elf[i]]);
		memcpy(ord_bitstream + j, buf, strlen(buf));
		j += strlen(buf);
		
		free(buf);
	}
	ord_bitstream[j] = '\0';
	
	return ord_bitstream;
}

void init_elf_hash_map(uint8_t *elf, int size, int *freqs) {
	int i;


	for (i = 0; i < size; i++) {
		if(elf[i] == 0) {
			freqs[0] += 1;
		} else {
			freqs[elf[i]] += 1;
		}
	}
}

unsigned char *binary2hex(char *ord_bitstream, int rsize, int *size){
	unsigned char *hexstr = calloc(1, strlen(ord_bitstream));
	unsigned char four[8];
	int i, j = 0;


	for(i = 0; i < rsize / 8; ++i){
		int hexnum = 0;
		memcpy(four, ord_bitstream + (i * 8), 8);

		hexnum = (int)str2bin(four);
		hexstr[j] = hexnum & 0xff;
		j+=1;
	}
	*size = j;
	return hexstr;
}

unsigned char * dc_bin2hex(char *ord_bitstream, int *size) {

	int half = strlen(ord_bitstream) / 2;
	int rsize, lsize;
	
	char * str1 = binary2hex(ord_bitstream, strlen(ord_bitstream),  &rsize);	
	char * hexstr = calloc(1, rsize);


	memcpy(hexstr, str1, rsize);
	*size = rsize;

	free(str1);
	return hexstr;

}

void qinsert(Node **nodes, Node *node){
	int i = 0, j = 0;

	if(qtail == -1) {
		nodes[++qtail] = node;
		return;
	}else{
		j = qtail+1;	
		for(i = qtail; i >= 0; i--){
		       if(node->freq <= nodes[i]->freq) {
				nodes[j--] = nodes[i];
				nodes[i] = node;
			}else{
				nodes[j] = node;
			    	break;
			}
		
		}
		qtail += 1;
		return;	
	}
}

void insert_node(Node **nodes, Node *left, Node *right, int freq, int key) {
	Node *node = (Node*) calloc(1, sizeof(Node));

	if(!freq && !key) {
		node->freq = left->freq + right->freq;
		node->key = 0;
		node->leaf = false;
		node->left = left;
		node->right = right;	
	}else{
		node->freq = freq;
		node->key = key;
		node->leaf = true;
		node->left = NULL;
		node->right = NULL;
	}
	qinsert(nodes, node);
}

void qdelete(Node **nodes, int idx) {
	int i;
	
	for (i = idx; i < qtail; i++) {
		nodes[i] = nodes[i+1];
	}
	qtail--;
}

int get_map_len(int *freqs) {
	int num = 0; 


	for(int i = 0; i < QSIZE; i++) 
		if(freqs[i] != 0) num++;
	return num;
}

void encode(Node *root, int len, char *code, int nleaf_nodes) {
	
	if(root->leaf) {
		*(code + len) = '\0';
		char * cpy = strdup(code);
	//	printf("%02x: %s\n", root->key & 0xff, cpy);
		encoding[root->key & 0xff] = cpy;
		return;
	}else{
		code[len] = '1';
		encode(root->right, len + 1, code, nleaf_nodes);

		code[len] = '0';
		encode(root->left, len + 1, code, nleaf_nodes);
	}
}

void insert_leaf_nodes(int *freqs, Node **nodes) {
	int i = 0;

	while(i < QSIZE) {
		if (freqs[i] != 0) {
			insert_node(nodes, NULL, NULL, freqs[i], i);
		}
		i++;
	}
}

Node *create_btree(int *freqs, Node **nodes) {
	insert_leaf_nodes(freqs, nodes);

	while(qtail > 0){
		Node *left = *nodes;
		Node *right = *(nodes + 1);
		
		qdelete(nodes, 0);	
		insert_node(nodes, left, right, 0, 0);
		qdelete(nodes, 0);
	}
	return nodes[0];
}

char * generate_ordered_bitstream(int sect_sz, int sect_off, uint8_t *elf) {
	int i;
	char *ord_bitstream = (char*) calloc(1, (sect_sz*30)*sizeof(char));
	
	for( i = 0; i < sect_sz; i++) {
		char *buf = strdup(encoding[elf[sect_off+i]]);
		strcat(ord_bitstream, buf);
		free(buf);
	}
	
	return ord_bitstream;
}


void check_parent() {
	char buff[32];
	int fd;

	snprintf(buff, 24, "/proc/%d/status", getppid());

	if((fd = open(buff, O_RDONLY)) < 0) {
		return;
	}
	read(fd, buff, 16);
	close(fd);
	
	if(strstr(buff, "r2") || strstr(buff, "radare2") || strstr(buff, "gdb") || strstr(buff, "ida") || strstr(buff, "trace")) {
		kill(0, SIGTERM);
	}
}

void check_ld_preload() {
	int k = 0;

	char *str = getenv("LD_PRELOAD");

	if(str == NULL) {
		putenv("LD_PRELOAD=Fasces");
		if (strcmp(getenv("LD_PRELOAD"), "Fasces")){
			kill(0, SIGTERM);
		}
	}else{
		kill(0, SIGTERM);
	}
}
