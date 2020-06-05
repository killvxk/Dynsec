include ksamd64.inc
EXTERN hook_routine:NEAR

.code
hook_wrapper PROC
	pushfq
	push rax
	push rcx
	push rdx
	push r8
	push r9
	push r11
	sub rsp,28h
	mov rcx, r10 ; return address
	mov rdx, rax ; return value
	push r10
	call hook_routine ; we call the cpp code
	pop r10
	add rsp,28h
	pop r11
	pop r8
	pop r9
	pop rdx
	pop rcx
	pop rax
	popfq
	jmp r10 ; goto return address
hook_wrapper ENDP

END