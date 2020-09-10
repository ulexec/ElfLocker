
[bits 32]

global rc4_key:data
global rc4_size:data
global start_rc4:data

extern check_hardware_breakpoints
extern sigfpe_handler
extern fork
extern exit
extern kill
extern waitpid
extern sleep
extern ptrace
extern malloc
extern munmap
extern ul_exec
extern getpid
extern anti_attach
extern decode_bin
extern create_btree
extern get_map_len
extern set_sigfpe
extern _etext,_edata, _end
extern puts

%define WUNTRACED 	2
%define SIGKILL		9
%define SIGTERM		15
%define SYS_mmap2	192
%define SYS_clone	120
%define MAX_THREADS	20		;number of threads
%define STACK_SIZE	(4096)		; stack size for each thread
%define PTRACE_ATTACH	0x00000010
%define PTRACE_TRACEME	0x00000000
%define PTRACE_CONT	0x00000007
%define CLONE_VM	0x00000100
%define CLONE_FS	0x00000200
%define CLONE_FILES	0x00000400
%define CLONE_SIGHAND	0x00000800
%define CLONE_PARENT	0x00008000
%define CLONE_THREAD	0x00010000
%define CLONE_IO	0x80000000
%define MAP_GROWSDOWN	0x0100
%define MAP_ANONYMOUS	0x0020
%define MAP_PRIVATE	0x0002
%define MAP_SHARED      0x0001
%define PROT_READ	0x1
%define PROT_WRITE	0x2
%define PROT_EXEC	0x4
%define THREAD_FLAGS \
 CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_PARENT|CLONE_THREAD

section .crypter progbits exec
global _start
_start:  
	lea edi, [imageBase]
	lea eax, [_etext]
	xor edx, edx
	dec edx
	shr edx, 52
	shl edx, 52
	and eax, edx
	stosd				; storing image base
	lea esi, [eax + 8]
	mov ecx, 2

    .mini_init:				; initialising next 2 global variables from elf header
	lodsd				; retrieving fields from header
	cmp ecx, 1
	jz .first
	add eax, [imageBase]	
    .first:
	stosd		
    loop .mini_init
	
	mov edi, [imageBase]
	add edi, 0x20
	mov esi, [edi]
	mov [rc4_size], esi
	add edi, 4
	mov esi, [edi]
	add esi, [imageBase]
	mov [rc4_key], esi
	mov eax, after_rc4
	mov [start_rc4], eax
	xor eax, eax
	inc eax
	shl eax, 10
	mov [dict_size], eax
	add eax, [dict_addr]	; calculating address of frequency table
	mov [blob_addr], eax
	mov eax, [esp]
	mov [argc], eax
	mov eax, esp
	add eax, 4
	mov [argv], eax
	mov eax, [eax]
	mov [appname], eax
	mov eax, esp
	add eax, 12
	mov [envp], eax
	call sigfpe_handler

	xor esi, esi
	idiv esi
	call after_rc4
	ret

section .text progbits exec

after_rc4:
	call check_hardware_breakpoints
	call alloc_shareable_chunk	; creating shareble chunk for threads to check checksum
	mov [shared], eax
	call compute_checksum
	mov ebx, [shared]
	mov [ebx], eax
	push decompression-0x200
	call deploy_threads
	ret
_exit:	
	push 0x0
	call exit
		
killpid:
	push SIGTERM
	push 0x0
	call kill
	ret

deploy_threads:
	pop eax
	pop eax
	mov [pivot], eax
	or ebp, MAX_THREADS
   .create:
	mov ebx, threadfn
	call thread_create
	dec ebp
	test ebp, ebp
	jnz .create
	mov eax, [pivot]
	add eax, 0x200
	jmp eax

threadfn:
    call compute_checksum
	mov ebx, [shared]
	mov ebx, [ebx]
    cmp ebx, eax
    jnz .notequal
    jmp threadfn
    .notequal:
	push SIGKILL
	xor eax, eax
	push eax
	call kill
	ret

thread_create:
	push ebx
	call stack_create
	lea ecx, [eax + STACK_SIZE - 8]
	pop dword [ecx]
	mov ebx, THREAD_FLAGS
	mov eax, SYS_clone
	int 0x80
	ret

stack_create:
	mov ebx, 0
	mov ecx, STACK_SIZE
	mov edx, PROT_WRITE | PROT_READ
	mov esi, MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN
	mov eax, SYS_mmap2
	int 0x80
	ret

alloc_shareable_chunk:
	mov ebx, 0
	mov ecx, 0x1000
	mov edx, PROT_WRITE | PROT_READ
	mov esi, MAP_ANONYMOUS | MAP_SHARED
	mov eax, SYS_mmap2
	int 0x80
	ret

compute_checksum:
	xor edx, edx
	xor eax, eax
	mov ecx, _etext 
	mov esi, after_rc4
	sub ecx, esi
    .compute:
	lodsb
	add edx, eax
    loop .compute
	mov eax, edx
	ret

decompression:		; decompression routines
	mov ebx, [blob_addr]
	push ebx
	mov ebx, [blob_size]
	push ebx
	mov ebx, [dict_addr]
	push ebx
	call decompress		; calling to decompress buff	
	mov eax, [envp]
	push eax
	mov eax, [argv]
	push eax
	mov eax, [argc]
	push eax
	mov eax, [decoded_size]
	push eax
	mov eax, [decoded]
	push eax
	mov eax, [argv]
	push eax
	call check_hardware_breakpoints
	call ul_exec
	call _exit

decompress:
	mov [pivot], esp
	mov ecx, [esp + 8]
	shl ecx, 2
	push ecx
	call malloc
	test eax, eax
	jz _exit
	mov [decoded], eax

	mov ecx, [esp + 4]	;dict_addr
	push ecx
	call get_map_len

	push eax
	call malloc
	test eax, eax
	jz _exit
	mov [nodes], eax       	; allocating memory for node structure
	
	push eax
	mov ecx, [dict_addr]
	push ecx
	call create_btree

	mov ebx, [decoded]
	push ebx	
	mov ebx, [blob_size]	
	add ebx, 100
	push ebx
	mov ebx, [blob_addr]
	push ebx
	push eax
	push eax
	call check_hardware_breakpoints
	call decode_bin
	mov [decoded_size], eax

	mov esp, [pivot]
	ret

section .data progbits write
	imageBase: 	dd 0x0
	dict_addr: 	dd 0x0
	blob_size:	dd 0x0
	dict_size: 	dd 0x0
	blob_addr: 	dd 0x0
	nodes: 	   	dd 0x0
	decoded:   	dd 0x0
	decoded_size: 	dd 0x0
	argc:		dd 0x0
	argv:		dd 0x0
	envp:		dd 0x0
	appname:	dd 0x0
	pivot:		dd 0x0
	ppid:		dd 0x0
	checksum: 	dd 0x0
	shared: 	dd 0x0
	rc4_key:	dd 0x0
	rc4_size:	dd 0x0
	start_rc4	dd 0x0

