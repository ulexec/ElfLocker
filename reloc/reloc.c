#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <elf.h>

#include <capstone/capstone.h>

#define DEBUG 	1
#define PDBG(fmt, ...) \
        do {							 	\
	    if (DEBUG) 							\
		fprintf(stderr, "%s:%d:%s()\t:" fmt, __FILE__, 		\
                                __LINE__, __func__, __VA_ARGS__); 	\
	} while (0);

void export_file(uint8_t *elf, int size, char* name) {
	int fd;

	fd = open(name , O_WRONLY | O_CREAT, S_IRWXU | S_IRWXG);
	write(fd, elf, size);
	close(fd);
	
	return;
}

uint8_t* alloc_file(int *fd, struct stat *st, uint8_t *filename) {	
	uint8_t *elf;

	if((*fd = open(filename, O_RDWR)) < 0) {
		perror("open");
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
	
typedef struct {
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr;
	Elf32_Phdr *phdr;
	Elf32_Phdr *code;
	Elf32_Phdr *data;
	Elf32_Phdr *dynamic;
	uint8_t *elf;
	uint8_t *filename;
	uint32_t oimage_base;
	uint32_t timage_base;
	uint32_t palign;
	uint32_t delta;
	uint32_t text_offset;
	int fd;
	struct stat st;
	csh handle;
	cs_insn *insn;
} Elf32_Obj;

static int get_operand_offset(uint32_t operand_value, uint8_t *instr_bytes, size_t instr_size) {
	int count = 0, nbytes = 0;

	for( int i = 0; i < instr_size; i++) {
		if(operand_value ==  *(uint32_t*)&instr_bytes[i]) {
			return i;
		}
	}
	return 0;
}

static void patch_code_absolute_operands(Elf32_Obj *obj, cs_mode mode, cs_insn *ins) {
	int count, i, instruction_offset;
	uint32_t section_offset, operand_offset;
	cs_x86 *x86;
	csh ud = obj->handle;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	x86 = &(ins->detail->x86);
	instruction_offset = ins->address - obj->timage_base;

	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &(x86->operands[i]);
		switch((int)op->type) {	
			case X86_OP_IMM:
				if ((op->imm & 0xfff00000) == (obj->oimage_base & 0xfff00000)) {
         				//printf("0x%"PRIx64":\t%s\t\t%s\nsize: %d\n", ins->address, ins->mnemonic, ins->op_str, ins->size); 
					//printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
					operand_offset = get_operand_offset(op->imm, ins->bytes, ins->size);
					*(uint32_t*)(obj->elf + instruction_offset + operand_offset) = op->imm + obj->delta;
					//printf("%lx\n", *(uint32_t*)(obj->elf + opcode_offset -1));
					//printf("\t\toperand patched: 0x%lx\n", *(uint32_t*)(obj->elf + instruction_offset + operand_offset));
				}	
			break;
			case X86_OP_MEM:
				if (op->mem.disp)
					if ((op->mem.disp & 0xfff00000) == (obj->oimage_base & 0xfff00000)){
         					//printf("0x%"PRIx64":\t%s\t\t%s\nsize: %d\n", ins->address, ins->mnemonic, ins->op_str, ins->size); 
						//printf("\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n", i, op->mem.disp);
						operand_offset = get_operand_offset(op->mem.disp, ins->bytes, ins->size);
						*(uint32_t*)(obj->elf + instruction_offset + operand_offset) = op->mem.disp + obj->delta;
						//printf("\t\toperand patched: 0x%lx\n", *(uint32_t*)(obj->elf + instruction_offset + operand_offset));
					} 
			break;
		}

	}
}


int reloc_code_section(Elf32_Obj *obj, Elf32_Shdr *shdr) {
	int count, i, j;
	cs_x86 *x86;

	count = cs_disasm(obj->handle, obj->elf + shdr->sh_offset, shdr->sh_size, obj->timage_base + shdr->sh_offset, 0, &obj->insn);  	
	if (count > 0) {
      		for (j = 0; j < count; j++) {
	 			patch_code_absolute_operands(obj, CS_MODE_32, &obj->insn[j]);
      		}
      		cs_free(obj->insn, count);
	} else {
      		printf("ERROR: Failed to disassemble given code!\n");
 		return -1;
	}
	return 0;
}

static void reloc_data_section(Elf32_Obj *obj, Elf32_Shdr *shdr) {
	uint8_t *current_val;
	int increment = 0;
	
	for (int i = 0; i < shdr->sh_size; i +=2 ) {
		current_val = obj->elf + shdr->sh_offset + i;
		if ((*(uint32_t*)current_val & 0xfff00000) == (obj->oimage_base & 0xfff00000)){
			//printf("[+] Pointer found: %llx\n", *(uint32_t*)current_val);
			*(uint32_t*)current_val += obj->delta;
			//printf("[+] Pointer relocated: %llx\n", *(uint32_t*)current_val);
		}
	}

}

int reloc_code_segment(Elf32_Obj *obj) {
	uint8_t *shstrtab;
	int i;
	printf("[*] Relocating CODE segment\n");

	shstrtab = (uint8_t*)(&obj->elf[obj->shdr[obj->ehdr->e_shstrndx].sh_offset]);
	for (i = 0; i < obj->ehdr->e_shnum; i++) {
		if (obj->shdr[i].sh_flags & SHF_EXECINSTR) {
			printf ("\t[+] Relocating section %s\n", &shstrtab[obj->shdr[i].sh_name]);
			reloc_code_section(obj, &obj->shdr[i]);
		}
	}

	return 0;
}

static void reloc_data_segment(Elf32_Obj *obj) {
	Elf32_Phdr *phdr = obj->data;
	uint8_t *current_val;
	uint8_t *shstrtab;
	int i;

	printf("\n[*] Relocating Data segment\n");
	
	shstrtab = (uint8_t*)(&obj->elf[obj->shdr[obj->ehdr->e_shstrndx].sh_offset]);
	for (i = 0; i < obj->ehdr->e_shnum; i++) {
		if (obj->shdr[i].sh_flags & SHF_EXECINSTR) {
			continue;
		} else {
			printf ("\t[+] Relocating section %s\n", &shstrtab[obj->shdr[i].sh_name]);
			reloc_data_section(obj, &obj->shdr[i]);
		}
	}
}



int relocate(uint8_t *filename, int32_t timage_base, uint8_t *output_file) {
	Elf32_Obj *obj = (Elf32_Obj*)calloc (1, sizeof(Elf32_Obj));
	Elf32_Phdr *phdr;
	Elf32_Shdr *shdr;
	uint8_t *shstrtab;
	int i, j;

	PDBG ("[*] Mapping %s\n", filename);
	
	obj->filename = filename;
	obj->elf = alloc_file(&obj->fd, &obj->st, obj->filename);
	obj->ehdr = (Elf32_Ehdr*)obj->elf;	
	obj->shdr = (Elf32_Shdr*)(obj->elf + obj->ehdr->e_shoff);
	obj->phdr = (Elf32_Phdr*)(obj->elf + obj->ehdr->e_phoff);
	obj->timage_base = timage_base;

	for (i = 0; i < obj->ehdr->e_phnum; i++) {
		phdr = (Elf32_Phdr*)&obj->phdr[i];
		switch(phdr->p_type) {
			case PT_LOAD:
				if (!phdr->p_offset) {
					obj->oimage_base = phdr->p_vaddr;
					obj->code = phdr;
					obj->palign = phdr->p_align;
				} else {
				 	obj->data = phdr;
			 	}
			break;			
		}
	}
	
	PDBG ("[+] Original ImageBase mapped at 0x%x\n", obj->oimage_base);
	obj->delta = (obj->oimage_base > timage_base) ? (obj->oimage_base - timage_base) * -1
									: timage_base - obj->oimage_base;
	PDBG ("[*] Relocation delta: %x -- %x\n", obj->delta, obj->oimage_base + obj->delta);
 	
 	if (cs_open(CS_ARCH_X86, CS_MODE_32, &obj->handle) != CS_ERR_OK) {
      		return -1;
	}
	cs_option(obj->handle, CS_OPT_DETAIL, CS_OPT_ON);

	reloc_code_segment(obj);
	reloc_data_segment(obj);

	for (i = 0; i < obj->ehdr->e_phnum; i++) {
		phdr = (Elf32_Phdr*)&obj->phdr[i];
		switch(phdr->p_type) {
			case PT_LOAD:
				if (!phdr->p_offset) {
					*(uint32_t*)&phdr->p_vaddr = obj->timage_base;
					*(uint32_t*)&phdr->p_paddr = obj->timage_base;
				} else {
					*(uint32_t*)&phdr->p_vaddr += obj->delta;
					*(uint32_t*)&phdr->p_paddr += obj->delta;	
				}
			break;
			case PT_GNU_STACK:
			break;
			default:
				 	*(uint32_t*)&phdr->p_vaddr += obj->delta;
					*(uint32_t*)&phdr->p_paddr += obj->delta;
			break;			
		}
	}
	
	for (i = 0; i < obj->ehdr->e_shnum; i++) {
		shdr = (Elf32_Phdr*)&obj->shdr[i];
		if (shdr->sh_addr) {
			*(uint32_t*)&shdr->sh_addr += obj->delta;
		}
	}

	*(uint32_t*)&obj->ehdr->e_entry += obj->delta;
	export_file(obj->elf, obj->st.st_size, output_file);
  
  	cs_close(&obj->handle);
	free (obj);

	return 0;
}

int main(int argc, char **argv) {
	uint8_t *elf;
	uint8_t *filename, *output_file;
	int32_t target_image_base;	
		if (argc != 4) {
		printf("[*] Usage: %s <elf to rebase> <target image_base> <output filename>\n", argv[0]);
		return 0;
	}

	filename = strdup (argv[1]);
	output_file =  strdup(argv[3]);
	target_image_base = strstr (argv[2], "0x") ? strtoll (argv[2], NULL, 0) 
						   : strtoll (argv[2], NULL, 16);
	target_image_base &= 0xfffff000;

	if (target_image_base > 0xc0000000) {
		printf ("[-] ImageBase is too big. it overlaps with kernel space (0xc0000000)\n");
		free (filename);
		return -1;
	}

	/*if (target_image_base < 0x10000000) {
		printf ("[-] ImageBase is too small. (0x00100000)\n");
		free (filename);
		return -1;
	}*/


	PDBG ("[+] relocating: %s to imagebase 0x%lx\n", filename, (void*)target_image_base);
	relocate (filename, target_image_base, output_file);

	free (filename);	
	free (output_file);	
}
