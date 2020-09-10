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
#include "../include/huffman_encoding.h"
#include "../include/block_cipher.h"

void file_export(uint8_t *elf, int size, char* name) {
	int fd;

	fd = open(name , O_RDWR | O_CREAT, S_IRUSR | S_IRGRP | S_IROTH);
	write(fd, elf, size);
	close(fd);
	
	return;
}

uint8_t* alloc_file(int *fd, struct stat *st, const char *filename) {	
	uint8_t *elf;

	if((*fd = open(filename, O_RDWR)) < 0) {
		perror("exit");
		exit(-1);
	}
	
	if(fstat(*fd, st) < 0) {
		perror("fstat");
		exit(-1);
	}
	
	if((elf = mmap(NULL, st->st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, *fd, 0)) == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}	
	
	return elf;
}

int encrypt_text(uint8_t *elf, int *addr)  {
	int i, j, size = 0, offset = 0;
	uint8_t *off, *strtab;
	Elf32_Shdr *shdr;

	Elf32_Ehdr *ehdr = (Elf32_Ehdr*)elf;	
	shdr = (Elf32_Shdr*)&elf[ehdr->e_shoff];
	strtab = (char*)(&elf[shdr[ehdr->e_shstrndx].sh_offset]);

	for(i = 1; i < ehdr->e_shnum; i++){
		if (strstr(&strtab[shdr[i].sh_name], ".text")) {
			size = shdr[i].sh_size;
			offset = shdr[i].sh_offset;
			*addr = shdr[i].sh_addr;
		}
	}
	off = (uint8_t*)((char*)elf + offset);

	encrypt_buff(off, size);
	return size;
}

int encript_lookup(uint8_t *elf, unsigned int *addr) {
	int i, j, size = 0, offset = 0;
	uint8_t *off, *strtab;
	Elf32_Shdr *shdr;

	Elf32_Ehdr *ehdr = (Elf32_Ehdr*)elf;	
	shdr = (Elf32_Shdr*)&elf[ehdr->e_shoff];
	strtab = (char*)(&elf[shdr[ehdr->e_shstrndx].sh_offset]);

	for(i = 1; i < ehdr->e_shnum; i++){
		if (strstr(&strtab[shdr[i].sh_name], ".switch_main")) {
			size = shdr[i].sh_size;
			offset = shdr[i].sh_offset;
			*addr = shdr[i].sh_addr;
		}
	}
	off = (uint8_t*)((char*)elf + offset);

	encrypt_buff(off, size);
	return size;
}

int encript_case9(uint8_t *elf, unsigned int *addr) {
	int i, j, size = 0, offset = 0;
	uint8_t *off, *strtab;
	Elf32_Shdr *shdr;

	Elf32_Ehdr *ehdr = (Elf32_Ehdr*)elf;	
	shdr = (Elf32_Shdr*)&elf[ehdr->e_shoff];
	strtab = (char*)(&elf[shdr[ehdr->e_shstrndx].sh_offset]);

	for(i = 1; i < ehdr->e_shnum; i++){
		if (strstr(&strtab[shdr[i].sh_name], ".case9")) {
			size = shdr[i].sh_size;
			offset = shdr[i].sh_offset;
			*addr = shdr[i].sh_addr;
		}
	}
	off = (uint8_t*)((char*)elf + offset);

	for (int i = 0; i < size; i++) {
		*(uint8_t*)(off + i) ^= 0xff;
	}
	return size;
}

int main (int argc, char **argv) {
	uint8_t *elf1, *elf2, *f;
	struct stat st1, st2;
	int fd1, fd2, i, stub_size,
	    nleaf_nodes, freqs[0x100] = {0},
	    elf_offset, elf_align, text_size, text_addr, prev_code;
	char *ord_bitstream, *c, *hexstr;
	Elf32_Ehdr *ehdr1, *ehdr2, *ehdr3;
	Elf32_Phdr *phdr, *code;
	Elf32_Shdr *shdr;
	Node **nodes;	

	if(argc != 4) {
		fprintf(stderr, "Usage %s <ux laucher> <file to compress> <output filename>\n", argv[0]);
		exit(0);
	}

	if((f = mmap(NULL, 0x10000000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0)) == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}	

	elf1 = alloc_file(&fd1, &st1, argv[1]);
	elf2 = alloc_file(&fd2, &st2, argv[2]);

	if(elf1[0] != 0x7f && strcmp((char*)&elf1[1], "ELF")){
		fprintf(stderr, "[!] File 1 is not an elf file\n");
		exit(-1);
	}

	if(elf2[0] != 0x7f && strcmp((char*)&elf2[1], "ELF")){
		fprintf(stderr, "[!] File 2 is not an elf file\n");
		exit(-1);
	}

	ehdr1 = (Elf32_Ehdr*)elf1;
	ehdr2 = (Elf32_Ehdr*)elf2;
	
	if(ehdr2->e_machine != EM_386) {
		printf("[-] Nodus does not support Binaries that isn't x86.\n");
		exit(EXIT_FAILURE);
	}
	
	if(ehdr2->e_type != ET_EXEC) {
		printf("[-] Nodus does not support ET_DYN\n");
		exit(EXIT_FAILURE);
	}

	if(ehdr2->e_version != EV_CURRENT) {
		printf("[-] Not a \"current\" ELF file.\n");
		return -1;
	}

	if(ehdr2->e_ehsize != sizeof(Elf32_Ehdr) || ehdr2->e_phentsize != sizeof(Elf32_Phdr) || 
		ehdr2->e_phnum > 20) {
		printf("[-] Instubid ELF header sizes\n");
		return -1;
	}
	memset(elf2, 0, 4); // deleating magic header from blob
	printf("[+] ELF magic deleated from stub: (%s)\n", elf2);
	printf("[*] Packing file %s\n", argv[2]);
	phdr = (Elf32_Phdr*)&elf1[ehdr1->e_phoff];

	for (i = 0; i < ehdr1->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD && !phdr[i].p_offset) {
			code = &phdr[i];
			break;
		}
	}
	

	unsigned int case9_addr, case9_size;
	if(!(case9_size = encript_case9(elf1, &case9_addr))) {
		printf("[-] section .switch_main not found\n");
		exit(EXIT_FAILURE);
	}
	printf("[*] Target binary switch_main section @ 0x%x of size : %d encrypted\n", case9_addr,  case9_size);

	if(!(text_size = encrypt_text(elf2, &text_addr))){
		printf("[-] Text section target binary was not found\n");
		exit(EXIT_FAILURE);
	}
	printf("[*] Target binary text section @ 0x%x of size : %d encrypted\n",text_addr,  text_size);


	unsigned int lookup_addr, lookup_size;
	if(!(lookup_size = encript_lookup(elf1, &lookup_addr))) {
		printf("[-] section .switch_main not found\n");
		exit(EXIT_FAILURE);
	}
	printf("[*] Target binary switch_main section @ 0x%x of size : %d encrypted\n",lookup_addr,  lookup_size);


	printf("[*] compressing target binary via huffman encoding\n");
	decoding = (char*)calloc(sizeof(char), st2.st_size);
	c = (char*)calloc(sizeof(char), (st2.st_size*10));	
	
	printf("[+] Initialization of frequency table\n");
	init_elf_hash_map(elf2, st2.st_size, freqs);
	nleaf_nodes = get_map_len(freqs);	

	printf("[+] Length of frequency dictionary: %d\n", nleaf_nodes);
	nodes = (Node**)calloc(1, nleaf_nodes*sizeof(Node));

	printf("[+] Creating binary tree\n");
	Node *btree = create_btree(freqs, nodes); 

	printf("[+] Generating master tree\n");
	encode(btree, 0, c, nleaf_nodes);
	
	printf("[*] Generating bitstream of target file\n");	
	ord_bitstream = generate_elf_ordered_bitstream(elf2, st2.st_size);
	
	printf("[*] Converting bitstream into hex\n");	
	unsigned char *stub = dc_bin2hex(ord_bitstream, &stub_size);
	memset(ord_bitstream, '\0', strlen(ord_bitstream));	
	printf("[*] Compression ratio: %.2f%%\n", (float)stub_size / st2.st_size * 100);

	prev_code = code->p_filesz;
	code->p_filesz = code->p_memsz + stub_size + sizeof(freqs);
	code->p_memsz = code->p_filesz;

	code->p_flags = PF_X | PF_W | PF_R;
	elf_offset = prev_code;
	
	memmove(f + code->p_offset, elf1 + code->p_offset, prev_code);
	memmove(f + elf_offset, freqs, sizeof(freqs));
	memmove(f + elf_offset + sizeof(freqs), stub, stub_size);

	encrypt_buff((char*)f + elf_offset + sizeof(freqs), stub_size );
	encrypt_buff((char*)f + elf_offset + sizeof(freqs), stub_size );
	encrypt_buff((char*)f + elf_offset + sizeof(freqs), stub_size );
	encrypt_buff((char*)f + elf_offset + sizeof(freqs), stub_size );
	encrypt_buff((char*)f + elf_offset + sizeof(freqs), stub_size );
	encrypt_buff((char*)f + elf_offset + sizeof(freqs), stub_size );
	encrypt_buff((char*)f + elf_offset + sizeof(freqs), stub_size );
	encrypt_buff((char*)f + elf_offset + sizeof(freqs), stub_size );
	encrypt_buff((char*)f + elf_offset + sizeof(freqs), stub_size );

	ehdr3 = (Elf32_Ehdr*)f;	
	*(uint32_t*)&ehdr3->e_ident[8] = elf_offset;
	*(uint32_t*)&ehdr3->e_ident[12] = (uint32_t)(stub_size);
	*(uint8_t*)&ehdr3->e_ident[5]='\x02';
	*(uint32_t*)&ehdr3->e_shoff = (uint32_t)(text_addr);
	*(uint32_t*)&ehdr3->e_flags = (uint32_t)(text_size);

	ehdr3->e_phnum = 1;
	ehdr3->e_shnum = 0;
	ehdr3->e_shstrndx = 0;
	ehdr3->e_shentsize = 0;
	
	file_export(f, code->p_filesz, argv[3]);
	printf("[*] File exported with name %s\n", argv[3]);
}
