EXTERN syscall_value:DWORD
EXTERN syscall_address:QWORD

.code
	public MyNtAllocateVirtualMemory

MyNtAllocateVirtualMemory proc

	mov r10, rcx
	mov eax, [syscall_value]
	jmp qword ptr[syscall_address]

	ret

MyNtAllocateVirtualMemory endp
end