#include <iostream>
#include "windows.h"
#include "winternl.h"
#include "SyscallsNumbers.h"

// Parse PEB
// 
// Extract NTDLL.dll base address
// 
// calculate offset to the start of the EAT (Export Address Table) of the NTDLL.dll
// 
// find offset from the start of the EAT to the function we want
// 
// find offset from the start of the function we want to the "mov eax, <SSN>" and extract SSN


int main() 
{
    const char* FuncName = "NtMapViewOfSection";
    HMODULE hModule = GetModuleHandleA("ntdll.dll");
    FARPROC FunctionAddress = GetFuncAddress(hModule, FuncName);

    PVOID syscalladdress = (PVOID)((UINT_PTR)(FunctionAddress)+16);

    printf("0x%p\n", FunctionAddress);
    printf("0x%p\n\n", syscalladdress);

    /*----This is used to view the opcodes of the extracted function----*/
    unsigned char* OpCode = (unsigned char*)FunctionAddress;
    for(int i = 0; i < 24; i++)
    {
        printf("%02X ", OpCode[i]);
    }
    printf("\n");
    /*----This is used to view the opcodes of the extracted function----*/

    /*The following if is to check if the function starts with the opcodes that match "mov r10, rcx" */
    if (OpCode[0] == 0x4c && OpCode[1] == 0x8B && OpCode[2]==0xD1) {
        printf("[+]%s function is not hooked\n", FuncName);
        GetSyscallNumber(hModule, FunctionAddress); // <-- need to implement it
    }
    else {
        printf("[-]%s function is hooked\n", FuncName);
    }

    //printf("\n\n");
    //printf("%s Function Address: 0x%p\n", FuncName, FunctionAddress);

    //FuncName = "NtTraceEvent";
    //FunctionAddress = GetFuncAddress(hModule, FuncName);
    //printf("%s Function Address: 0x%p\n", FuncName, FunctionAddress);

    return 0;
}

