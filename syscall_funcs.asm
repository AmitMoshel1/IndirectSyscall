
EXTERN syscall_value:DWORD
EXTERN syscalladdress:QWORD

    .data
;        syscallvalue dd ?
;        syscalladdr  dq ?

.code
	public MyNtAllocateVirtualMemory

MyNtAllocateVirtualMemory proc
;	mov r10, rcx
;	mov eax, [rsp+56] ; some how eax register already contains the SSN so the line is commented
;	mov r13, qword ptr[rsp+64]
;	jmp r13
	
	mov r10, rcx
	mov eax, [syscall_value]
	jmp qword ptr[syscalladdress]

	ret

MyNtAllocateVirtualMemory endp
end