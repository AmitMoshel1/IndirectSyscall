#include <iostream>
#include "windows.h"
#include "winternl.h"
#include "SyscallsNumbers.h"

// Parse PEB
// 
// Extract NTDLL.dll base address
// 
// Get to the Export Address Table of the ntdll.dll
// 
// Extract the function address that we want to indirect syscall 
// 
// Get the SSN and the address of the "syscall" instruction of the Native API function

//extern "C" NTSYSAPI NTSTATUS NTAPI MyZwQuerySystemInformation(ULONG SystemInfoClass, PVOID SystemInfoBuffer, ULONG SystemInfoBufferSize, PULONG BytesReturned);
//extern "C" NTSTATUS MyNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,ULONG CreateDisposition,ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);


UINT_PTR syscalladdress;
DWORD syscall_value;

//extern "C" NTSYSCALLAPI NTSTATUS MyNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect, DWORD syscall_value, UINT_PTR syscalladdress);
extern "C" NTSTATUS MyNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect, DWORD syscall_value, UINT_PTR syscalladdress);

//extern VOID HellsGate(DWORD wSystemCall, UINT_PTR SyscallAddress);
//extern NTSTATUS HellsDescent();

BOOL IsFunctionHooked(const char * FuncName, unsigned char * OpCode)
{
    bool check1 = true;
    bool check2 = true;
    for (int i = 0; i < 24; i++)
    {
        if (OpCode[i] == 0xe9) //e9 == jmp instruction which means that the function is hooked
        {
            check1 = false;
            break;
        }

        if(OpCode[0] != 0x4c && OpCode[1] != 0x8B && OpCode[2] != 0xD1)
        {
            check2 = false;
        }
        if(check1 && check2)
        {
            printf("[+] %s function is not hooked\n", FuncName);
            return false;
        }
        printf("[-] %s function is hooked\n", FuncName);
        return true;
    }

}


int main() 
{

    const char* FuncName = "NtAllocateVirtualMemory";
    HMODULE hModule = GetModuleHandleA("ntdll.dll");
    
    FARPROC FunctionAddress = GetFuncAddress(hModule, FuncName);

    FARPROC FunctionAddress1 = (FARPROC)((UINT_PTR)(FunctionAddress)-0x20); // Address of function before it
    FARPROC FunctionAddress2 = (FARPROC)((UINT_PTR)(FunctionAddress)+0x20); // Address of function after it
    syscalladdress = (UINT_PTR)GetSyscallAddress(FunctionAddress);
    
    printf("Function before address: 0x%p\n", FunctionAddress1);
    printf("%s Function Address: 0x%p\n", FuncName, FunctionAddress);
   
    printf("Function after address: 0x%p\n", FunctionAddress2);
    printf("%s Syscall Address: 0x%p\n\n", FuncName, syscalladdress);

    /*----This is used to view the opcodes of the extracted function----*/
    unsigned char* OpCode = (unsigned char*)FunctionAddress;
    printf("\nOpCodes of %s:\n", FuncName);
    for(int i = 0; i < 24; i++)
    {
        printf("%02X ", OpCode[i]);
    }
    /*----This is used to view the opcodes of the extracted function----*/

    printf("\n\n");
    PVOID* baseaddr = NULL;
    SIZE_T buffSize = 0x1000;
    if (IsFunctionHooked(FuncName, OpCode)) { // remove the ! sign
        syscalladdress = (UINT_PTR)GetSyscallAddress(FunctionAddress);
        syscall_value = (DWORD)GetSyscallNumberHooked(FunctionAddress1, FunctionAddress2); // need to fix that
        printf("\nhooked function syscall: 0x%x\n", syscall_value);
    }
    else
    {
        syscalladdress = (UINT_PTR)GetSyscallAddress(FunctionAddress);
        syscall_value = (DWORD)OpCode[4];
        printf("unhhoked function's syscall: 0x%x\n", syscall_value);
        NTSTATUS a = MyNtAllocateVirtualMemory(GetModuleHandleA(NULL), baseaddr, (ULONG_PTR)0, &buffSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, syscall_value, syscalladdress);
        
                                                // rcx              rdx             r8                    r9      [rsp+0x28]   [rsp+0x30]        [rsp+0x38]                 [rsp+0x40]
        //NTSTATUS a = MyNtAllocateVirtualMemory(syscall_value, syscalladdress, GetModuleHandleA(NULL), baseaddr, (ULONG_PTR)0, &buffSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
 
        /*
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect
        .data
            syscallvalue dd ?
            syscalladdr  dq ?

        proc MyNtAllocateVirtualMemory
            mov [syscallvalue], rcx
            mov [syscalladdr], rdx

            mov rcx, r8             ; rcx = HANDLE ProcessHandle
            mov rdx, r9             ; rdx = PVOID *BaseAddress
            mov r8, [rsp+0x28]      ; r8 = ULONG_PTR ZeroBits
            mov r9, [rsp+0x30]      ; r9 = PSIZE_T RegionSize

            mov r13, [rsp+0x38]
            mov [rsp+0x28], r13     ; [rsp+0x28] = ULONG AllocationType

            mov r13, [rsp+0x40]
            mov [rsp+0x30], r13     ; [rsp+0x30] = ULONG Protect

            mov [rsp+0x38], 0
            mov [rsp+0x40], 0

            mov r10, rcx
            mov eax, syscallvalue
            jmp qword ptr[syscalladdr]

        endp MyNtAllocateVirtualMemory
        end
        
        */
        
        
        printf("NTSTATUS VALUE: %d\n", a);
        printf("Allocated address at: 0x%p\n", baseaddr);
        printf("test");
    }


    /*The following if is to check if the function starts with the opcodes that match "mov r10, rcx" 
      needs to improve the hooking detection
    */

    return 0;
}

