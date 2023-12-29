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

extern "C" UINT_PTR syscalladdress = 0;
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

    const char* FuncName = "NtAllocateVirtualMemory";
    HMODULE hModule = LoadLibraryA("ntdll.dll");
    
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
        //NTSTATUS a = MyNtAllocateVirtualMemory(GetModuleHandleA(NULL), baseaddr, (ULONG_PTR)0, &buffSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, syscall_value, syscalladdress);
        
        PVOID BaseAddress = NULL;
        SIZE_T buffSize = 0x1000;
        ULONG ZeroBits = 0;
        NTSTATUS a = MyNtAllocateVirtualMemory((HANDLE)-1, (PVOID*)&BaseAddress, (ULONG_PTR)0, &buffSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
        
        printf("NTSTATUS VALUE: %d\n", a);
        printf("Allocated address at: 0x%p\n", BaseAddress);

    }

    return 0;
}

