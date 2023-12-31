#include <iostream>
#include "windows.h"
#include "winternl.h"
#include "SyscallsNumbers.h"


extern "C" UINT_PTR syscall_address = 0;
extern "C" DWORD syscall_value = 0;
extern "C" NTSTATUS MyNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

BOOL IsFunctionHooked(const char * FuncName, unsigned char * OpCode)
{
    bool check1 = true;
    bool check2 = true;

    if (OpCode[0] != 0x4c && OpCode[1] != 0x8B && OpCode[2] != 0xD1)
    {
        check2 = false;
    }

    for (int i = 0; i < 24; i++)
    {
        if (OpCode[i] == 0xe9) //0xe9 == jmp instruction opcode which means that the function is hooked
        {
            check1 = false;
            break;
        }
    }
        if(check1 && check2)
        {
            printf("[+] %s function is not hooked\n", FuncName);
            return false;
        }
        printf("[-] %s function is hooked\n", FuncName);
        return true;
}


int main() 
{
    PVOID BaseAddress;
    SIZE_T buffSize;
    ULONG ZeroBits;
    char hexchars[] = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";

    const char* FuncName = "NtAllocateVirtualMemory";
    HMODULE hModule = LoadLibraryA("ntdll.dll");
    
    FARPROC FunctionAddress = GetFuncAddress(hModule, FuncName);

    /*----This is used to view the opcodes of the extracted function----*/
    unsigned char* OpCode = (unsigned char*)FunctionAddress;
    printf("\nOpCodes of %s:\n", FuncName);
    for(int i = 0; i < 24; i++)
    {
        printf("%02X ", OpCode[i]);
    }
    /*----This is used to view the opcodes of the extracted function----*/
    printf("\n\n");

    if (IsFunctionHooked(FuncName, OpCode)) {
        FARPROC FunctionAddress1 = (FARPROC)((UINT_PTR)(FunctionAddress)-0x20); // Address of function before it
        FARPROC FunctionAddress2 = (FARPROC)((UINT_PTR)(FunctionAddress)+0x20); // Address of function after it
        syscall_address = (UINT_PTR)GetSyscallAddress(FunctionAddress);

        printf("Function before address: 0x%p\n", FunctionAddress1);
        printf("Function after address: 0x%p\n\n", FunctionAddress2);

        printf("%s Function Address: 0x%p\n", FuncName, FunctionAddress);
        printf("%s Syscall Address: 0x%p\n\n", FuncName, syscall_address);

        syscall_address = (UINT_PTR)GetSyscallAddress(FunctionAddress);
        syscall_value = (DWORD)GetSyscallNumberHooked(FunctionAddress1, FunctionAddress2); // need to fix that
        printf("\nhooked %s function syscall: 0x%x\n", FuncName, syscall_value);
        printf("hooked %s syscall address: 0x%p\n", FuncName, syscall_address);

        BaseAddress = NULL;
        buffSize = 0x1000;
        ZeroBits = 0;
        NTSTATUS Result = MyNtAllocateVirtualMemory((HANDLE)-1, (PVOID*)&BaseAddress, (ULONG_PTR)0, &buffSize, 
                                                    (ULONG)(MEM_COMMIT | MEM_RESERVE),PAGE_EXECUTE_READWRITE);

        memcpy(BaseAddress, hexchars, sizeof(hexchars));

        printf("NTSTATUS VALUE: %d\n", Result);
        printf("Allocated address at: 0x%p\n", BaseAddress);
        printf("\n");
    }
    else
    {
        syscall_address = (UINT_PTR)GetSyscallAddress(FunctionAddress);
        syscall_value = (DWORD)GetSyscallNumberNotHooked(OpCode);
        printf("\nunhooked %s function syscall: 0x%x\n", FuncName, syscall_value);
        printf("unhooked %s syscall address: 0x%p\n", FuncName, syscall_address);

        BaseAddress = NULL;
        buffSize = 0x1000;
        ZeroBits = 0;
        NTSTATUS Result = MyNtAllocateVirtualMemory((HANDLE)-1, (PVOID*)&BaseAddress, (ULONG_PTR)0, &buffSize, 
                                                    (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
        
        memcpy(BaseAddress, hexchars, sizeof(hexchars));
        
        printf("\nNTSTATUS VALUE: %d\n", Result);
        printf("Allocated address at: 0x%p\n", BaseAddress);
        
        printf("\n");
    }
    return 0;
}

