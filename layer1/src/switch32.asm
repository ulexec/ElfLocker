[BITS 32]

global switch_main:function
global switch_main_size:data
global case9:function
global case9_end:function
extern image_base
extern ehdr
extern size
extern offset

extern check_hbreaks
extern check_parent
extern decrypt_buff
extern ul_exec
extern free
extern create_btree
extern sigaction
extern decode_bin
extern memset
extern check_ld_preload
extern get_map_len
extern calloc
extern s1
extern sigHandler


SA_SIGINFO	equ 0x00000040
SIGSEGV     equ 11
SIGTRAP     equ 5

struc Node
    .freq   resd    1
    .key    resb    1
    .leaf   resb    1
    .left   resd    1
    .right  resd    1
endstruc


struc Elf32_Ehdr
	.e_ident 		resb 	16
	.e_type 		resw 	1
	.e_machine 		resw 	1
	.e_version 		resd 	1
	.e_entry 		resd 	1
	.e_phoff 		resd 	1
	.e_shoff 		resd 	1
	.e_flags 		resd 	1
	.e_ehsize 		resw 	1
	.e_phentsize	resw 	1
	.e_phnum		resw 	1
	.e_shentsize	resw 	1
	.e_shnum 		resw 	1
	.e_shstrndx		resw 	1
endstruc

struc sigaction32
    .sa_handler     		resd    1
    .sa_sigaction   		resd    1
    .sa_mask        		resd    1
    .sa_flags       		resd    1
    .sa_restorer    		resd    1
endstruc

section .decrypter write alloc exec

switch_main:
    mov eax, esp
    add eax, 4 
    mov ebx, [eax]
    mov [argc], ebx
    add eax, 4
    mov ebx, [eax]
    mov [argv], ebx
    mov ecx, [ebx]
    mov [argv0], ecx
    add eax, 4
    mov eax, [eax]
    mov [envp], eax

    xor eax, eax
    mov [count], eax
    
    mov  eax, switch_main_size
    mov eax, [eax]
    push eax
    push while
    call decrypt_buff
    jmp while

section .switch_main write alloc exec
while:
    mov eax, [count]
    test eax, eax
    jl return

    mov ecx, switch_cases
    mov ebx, switch_lookout
    xlatb
    xlatb
    xlatb
    xlatb
    shl al, 2
    add ecx, eax
    jmp [ecx]



case1:
    mov eax, [image_base]
    add eax, [offset]
    mov ebx, [size]
    mov ecx, 0x100
    shl ecx, 2
    add eax, ecx
    push ebx
    push eax
    call decrypt_buff
    jmp iterate

case0:
    ;call check_parent
   
    mov eax, [image_base]
    add eax, [offset]
    mov ebx, [size]
    mov ecx, 0x100
    shl ecx, 2
    add eax, ecx
    push ebx
    push eax
    call decrypt_buff
    jmp iterate



case3:
    mov eax, [load_addr]
    mov [freqs], eax

    mov eax, size
    shl eax, 1
    push eax
    push 1
    call calloc
    mov [decoded], eax

    mov eax, [image_base] 
    add eax, [offset]
    mov ebx, [size]
    mov ecx, 0x100
    shl ecx, 2
    add eax, ecx
    push ebx
    push eax
    call decrypt_buff

    jmp iterate

case4:
    ;call check_ld_preload

    mov eax, [image_base] 
    add eax, [offset]
    mov ebx, [size]
    mov ecx, 0x100
    shl ecx, 2
    add eax, ecx
    push ebx
    push eax
    call decrypt_buff

    jmp iterate

case2:
    mov eax, [image_base]
    add eax, [offset]
    mov [load_addr], eax

    mov ebx, 0x100
    shl ebx, 2
    add eax, ebx    
    mov [compressed_buf], eax

    mov eax, [image_base]
    add eax, [offset]
    mov ebx, [size]
    mov ecx, 0x100
    shl ecx, 2
    add eax, ecx
    push ebx
    push eax
    call decrypt_buff

    jmp iterate

case7:
    push 0
    lea eax, [s1]
    push eax
    push SIGTRAP
    call sigaction
    test eax, eax
    jl exit

    mov eax, [image_base] 
    add eax, [offset]
    mov ebx, [size]
    mov ecx, 0x100
    shl ecx, 2
    add eax, ecx
    push ebx
    push eax
    call decrypt_buff

    jmp iterate

case5:
    mov eax, [freqs]
    push eax
    call get_map_len

    mov [nleaf_nodes], eax
    mov ebx, 0x10
    push eax
    push ebx
    call calloc
    mov [nodes], eax

    mov eax, [image_base] 
    add eax, [offset]
    mov ebx, [size]
    mov ecx, 0x100
    shl ecx, 2
    add eax, ecx
    push ebx
    push eax
    call decrypt_buff

    jmp iterate

case6:
    mov eax, [image_base] 
    add eax, [offset]
    mov ebx, [size]
    mov ecx, 0x100
    shl ecx, 2
    add eax, ecx
    push ebx
    push eax
    call decrypt_buff

    mov eax, [nodes]
    mov ebx, [freqs]
    push eax
    push ebx   
    call create_btree
    mov [btree], eax

    jmp iterate

case8:
    mov eax, [image_base] 
    add eax, [offset]
    mov ebx, [size]
    mov ecx, 0x100
    shl ecx, 2
    add eax, ecx
    push ebx
    push eax
    call decrypt_buff

    mov eax, [decoded]
    push eax
    mov eax, [size]
    push eax
    mov eax, [compressed_buf]
    push eax
    mov eax, [btree]
    push eax
    push eax
    call decode_bin
    mov [dsize], eax
    call check_hbreaks

case10:
    xor eax, eax
    xor ebx, ebx
    idiv ebx
    

iterate:
    add dword [count], 1
    jmp while

exit:
    xor eax, eax
    inc ebx
    int 0x80

return:
    ret

switch_cases:
    .case6 dd case6
    .case9 dd case9
    .case4 dd case4
    .case8 dd case8
    .case2 dd case2
    .case5 dd case5
    .case0 dd case0
    .case7 dd case7
    .case3 dd case3
    .case1 dd case1
    
    .case10 dd case6+15
    .case11 dd case9+30
    .case12 dd case4+32
    .case13 dd case8+120
    .case14 dd case2+45
    .case15 dd case5+34
    .case16 dd case0+322
    .case17 dd case7+655
    .case18 dd case3+321
    .case19 dd case1+123

switch_lookout db 4, 6, 8, 1, 3, 5, 2, 7, 9, 0, 10, 19, 18, 11, 12, 17, 16, 13, 15, 14
end:

section .text
dsize           dd  0
btree           dd  0
nodes           dd  0
nleaf_nodes     dd  0
freqs           dd  0
compressed_buf  dd  0
load_addr       dd  0
count           dd  0
envp            dd  0
argv            dd  0
argv0           dd  0
argc            dd  0
decoded         dd  0
switch_main_size dd end - while

section .case9
case9:
    push 0
    lea eax, [s1]
    push eax
    push SIGSEGV
    call sigaction
    test eax, eax
    jl exit

    mov eax, [envp]
    push eax
    mov eax, [argv]
    push eax
    mov eax, [argc]
    push eax
    mov eax, [dsize]
    push eax
    mov eax, [decoded]
    push eax
    mov eax, [argv0]
    push eax
    call ul_exec
 
    jmp iterate
case9_end:
    nop 
    nop
    nop
    


