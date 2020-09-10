CC=gcc
CFLAGS=-m32 --static -funroll-loops -Os -Wall -fno-stack-protector -c -Qn -fomit-frame-pointer -fno-exceptions -fno-asynchronous-unwind-tables -fno-unwind-tables

DIET=diet
DIETFLAGS=-m32 -funroll-loops -s -Wl,-T

AS=nasm
ASFLAGS=-felf32

LD=ld
LDFLAGS=-melf_i386 -s -no-ld-generated-unwind-info -T

all: layer1 layer2 final

layer1: rebased layer1_embed layer1_module
layer1_embed:
	$(CC) -m32 layer1/src/embed.c			\
		       layer1/src/block_cipher.c 	\
			   layer1/src/crc32_test.c      \
			   layer1/src/rc4_test.c 		\
			   -o bin/layer1_embed.bin	
layer1_module:
	$(AS) $(ASFLAGS) layer1/src/switch32.asm -o switch32.o
	$(CC) $(CFLAGS) layer1/src/hbreaks.c -o hbreaks.o
	$(DIET) $(CC) $(DIETFLAGS)  layer1/src/layer1.ld        \
		layer1/src/load.c             \
		layer1/src/save.c             \
		layer1/src/huffman.c          \
		layer1/src/ul_exec.c          \
		layer1/src/anti_debugging.c   \
		layer1/src/launcher.c         \
		layer1/src/block_cipher.c     \
		layer1/src/rc4_test.c         \
		layer1/src/crc32_test.c       \
		switch32.o                    \
		hbreaks.o                     \
	-o bin/layer1.bin
	bin/layer1_embed.bin bin/layer1.bin ./bin/crackme_rebased bin/layer1_test.bin
	chmod 777 bin/layer1_test.bin
    #bin/layer1_test.bin

rebased:
	$(CC) ./reloc/reloc.c -lcapstone -o ./bin/reloc
	./bin/reloc ./bin/crackme 0x13370000 ./bin/crackme_rebased

layer2: layer2_embed layer2_module
layer2_embed:
	$(CC) layer2/src/embed.c -o bin/layer2_embed.bin
layer2_module: 
	$(AS) $(ASFLAGS) layer2/src/launcher.asm -o layer2.o
	$(CC) $(CFLAGS) layer2/src/huffman.c -o huffman.o
	$(CC) $(CFLAGS) layer2/src/rc4.c -o rc4.o
	$(CC) $(CFLAGS) layer2/src/layer2_sigaction.c -o sigaction.o
	$(CC) $(CFLAGS) layer2/src/ul_exec.c -o ul_exec.o
	$(CC) $(CFLAGS) layer2/src/load.c -o load.o
	$(CC) $(CFLAGS) layer2/src/save.c -o save.o
	$(LD) $(LDFLAGS) layer2/src/layer2.ld	\
			  			layer2.o 			\
						rc4.o 				\
						huffman.o 			\
						ul_exec.o 			\
						load.o 				\
						save.o 				\
						sigaction.o			\
						layer2/src/libc.a -o bin/layer2.bin
	bin/layer2_embed.bin bin/layer2.bin ./bin/crackme bin/layer2_test.bin True
	#bin/layer2_embed.bin bin/layer2.bin ./crackme bin/layer2_test.bin True
	chmod 777 bin/layer2_test.bin
	#bin/layer2_test.bin

final:
	bin/layer2_embed.bin bin/layer2.bin bin/layer1_test.bin bin/crackme.elflocked
	chmod 777 bin/crackme.elflocked 
	bin/crackme.elflocked

clean:
	-rm ./*.o
cleanall: clean
	-rm bin/*

