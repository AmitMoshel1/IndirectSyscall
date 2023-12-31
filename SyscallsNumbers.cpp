#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "SyscallsNumbers.h"
#include <string.h>


/*ParsePEB is implemented but not used*/
HMODULE ParsePEB(char DLL) {
    PPEB PEBPtr = (PPEB)__readgsqword(0x60);
    const wchar_t* name;

    PPEB_LDR_DATA HeadModuleList = (PPEB_LDR_DATA)PEBPtr->Ldr;
    PLIST_ENTRY entry = &HeadModuleList->InMemoryOrderModuleList;

    HMODULE NtdllBase = NULL;
    DWORD baseaddress = ((uintptr_t)PEBPtr + 0x10);

    while (entry->Flink != &HeadModuleList->InMemoryOrderModuleList) {
        PLDR_DATA_TABLE_ENTRY table_entries = (PLDR_DATA_TABLE_ENTRY)entry->Flink;
        name = table_entries->FullDllName.Buffer;
        if (_wcsicmp(name, (wchar_t *)DLL) == 0) {
            HMODULE NtdllBase = (HMODULE)table_entries->DllBase;
            return NtdllBase;
        }
        entry = entry->Flink;
    }
    return NULL;
}

/*
Parsing the Export Address Table of ntdll.dll and iterating over the exported function's addresses.
for each function iterating inside the Export Address Table, comparing it to the value
of the function we want to execute through indirect syscall technique, then returning the address
of that function.
*/

FARPROC GetFuncAddress(HMODULE handle, const char* APIFunction)
{
    PVOID moduleBase = (PVOID)handle;

    PIMAGE_DOS_HEADER pDosHeaders = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((BYTE*)moduleBase + pDosHeaders->e_lfanew);

    PIMAGE_OPTIONAL_HEADER pOptionalHeaders = &pNtHeaders->OptionalHeader;

    PIMAGE_DATA_DIRECTORY pExportDirectory = (PIMAGE_DATA_DIRECTORY)&pOptionalHeaders->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY ExportAddressTable = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)handle + pExportDirectory->VirtualAddress);

    PDWORD FuncAddresses = (PDWORD)((BYTE*)handle + ExportAddressTable->AddressOfFunctions);
    PDWORD NameAddresses = (PDWORD)((BYTE*)handle + ExportAddressTable->AddressOfNames);

    DWORD NumberOfFunctions = ExportAddressTable->NumberOfFunctions;

    char* FuncName;
    for (DWORD i = 0; i < NumberOfFunctions; i++)
    {
        FuncName = reinterpret_cast<char*>(pOptionalHeaders->ImageBase + NameAddresses[i]);
        if (strcmp(FuncName, APIFunction) == 0)
        {
            return (FARPROC)(pOptionalHeaders->ImageBase + FuncAddresses[i+1]);
        }
    }    
    return NULL;
}

char *GetSyscallNumberHooked(FARPROC FuncAddress1, FARPROC FuncAddress2) 
{
    unsigned char* OpCode1 = (unsigned char*)FuncAddress1;
    unsigned char* OpCode2 = (unsigned char*)FuncAddress2;
    
    unsigned char Syscall1;
    unsigned char Syscall2;

    /* An if statement which checks if the SSN < 0x100 */
    if (OpCode1[5] == 0x00 && OpCode2[5] == 0x00) {
        Syscall1 = OpCode1[4];
        Syscall2 = OpCode2[4];
        printf("Syscall Number in the function Before: 0x%02X\n", Syscall1);
        printf("Syscall Number in the function after: 0x%02X\n", Syscall2);

        return (char*)(Syscall1 + 1);
    }

    unsigned int* syscall_expanded1 = (unsigned int*)(OpCode1 + 4);
    unsigned int* syscall_expanded2 = (unsigned int*)(OpCode2 + 4);

    printf("\nSpecial Syscall Number in the function Before: 0x%02X\n", *syscall_expanded1);
    printf("Special Syscall Number in the function After: 0x%02X\n", *syscall_expanded2);

    int SyscallNumber =  *(syscall_expanded1)+1;
    return (char*)SyscallNumber;

}

char* GetSyscallNumberNotHooked(unsigned char* OpCode)
{
    /*
    Function which returns the SSN of a function
    and checks whether the SSN < 0x100, if so returns the 5th byte of the OpCodes
    else, takes the 4th location and convert that to a word, which will return
    the SSN that is 3 figures.
    */
    unsigned char Syscall;
    if (OpCode[5] == 0x00) 
    {
        return (char *)OpCode[4];
    }
    unsigned int* syscall = (unsigned int*)(OpCode + 4);
    int SyscallNumber = *(syscall);
    return (char*)SyscallNumber;
}

PVOID GetSyscallAddress(FARPROC address) 
{
    unsigned char* OpCode = (unsigned char*)address;

    while(OpCode[0] != 0x0F && OpCode[1] != 05)
    {
        address = (FARPROC)((UINT_PTR)address+1);
        OpCode = (unsigned char*)address;
    }
    return address;
}


